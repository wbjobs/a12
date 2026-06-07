package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../bpf/network_trace.bpf.c -- -I../bpf

type Tracer struct {
	objs         *bpfObjects
	links        []link.Link
	perfReader   *perf.Reader
	eventChan    chan *model.RawTraceEvent
	stopChan     chan struct{}
	eventHandler func(*model.RawTraceEvent)
	mu           sync.Mutex
	running      bool
}

func NewTracer(cfg *config.EBPFConfig) (*Tracer, error) {
	t := &Tracer{
		eventChan: make(chan *model.RawTraceEvent, 10000),
		stopChan:  make(chan struct{}),
	}

	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading bpf spec: %w", err)
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/ebpf-apm",
		},
	}); err != nil {
		return nil, fmt.Errorf("loading and assigning bpf objects: %w", err)
	}
	t.objs = &objs

	t.links = make([]link.Link, 0)

	kprobes := []struct {
		name string
		fn   interface{}
	}{
		{"tcp_connect", t.objs.TcpConnect},
		{"tcp_connect_ret", t.objs.TcpConnectRet},
		{"tcp_accept", t.objs.TcpAccept},
		{"udp_sendmsg", t.objs.UdpSendmsg},
		{"udp_recvmsg", t.objs.UdpRecvmsg},
		{"tcp_sendmsg", t.objs.TcpSendmsg},
		{"tcp_cleanup_rbuf", t.objs.TcpCleanupRbuf},
		{"tcp_close", t.objs.TcpClose},
	}

	for _, kp := range kprobes {
		var l link.Link
		var err error

		if kp.name == "tcp_connect_ret" {
			l, err = link.Kretprobe(kp.name, kp.fn, nil)
		} else {
			l, err = link.Kprobe(kp.name, kp.fn, nil)
		}

		if err != nil {
			return nil, fmt.Errorf("creating kprobe %s: %w", kp.name, err)
		}
		t.links = append(t.links, l)
		log.Printf("Attached kprobe: %s", kp.name)
	}

	reader, err := perf.NewReader(t.objs.Events, cfg.PerfBufferSize)
	if err != nil {
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}
	t.perfReader = reader

	return t, nil
}

func (t *Tracer) SetEventHandler(handler func(*model.RawTraceEvent)) {
	t.eventHandler = handler
}

func (t *Tracer) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return fmt.Errorf("tracer already running")
	}
	t.running = true
	t.mu.Unlock()

	go t.pollEvents(ctx)

	log.Println("eBPF tracer started successfully")
	return nil
}

func (t *Tracer) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}
	t.running = false

	close(t.stopChan)

	for _, l := range t.links {
		if err := l.Close(); err != nil {
			log.Printf("Warning: closing link: %v", err)
		}
	}

	if t.perfReader != nil {
		if err := t.perfReader.Close(); err != nil {
			log.Printf("Warning: closing perf reader: %v", err)
		}
	}

	if t.objs != nil {
		if err := t.objs.Close(); err != nil {
			log.Printf("Warning: closing bpf objects: %v", err)
		}
	}

	close(t.eventChan)
	log.Println("eBPF tracer stopped")
	return nil
}

func (t *Tracer) pollEvents(ctx context.Context) {
	cfg := config.AppConfig.EBPF
	pollTimeout := time.Duration(cfg.PollTimeoutMs) * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopChan:
			return
		default:
			record, err := t.perfReader.ReadTimeout(pollTimeout)
			if err != nil {
				if perf.IsClosed(err) {
					return
				}
				if err, ok := err.(unix.Errno); ok && err == unix.ETIME {
					continue
				}
				log.Printf("Error reading perf record: %v", err)
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("Lost %d samples", record.LostSamples)
			}

			event, err := parseRawEvent(record.RawSample)
			if err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			if t.eventHandler != nil {
				t.eventHandler(event)
			}

			select {
			case t.eventChan <- event:
			default:
				log.Printf("Event channel full, dropping event")
			}
		}
	}
}

func (t *Tracer) Events() <-chan *model.RawTraceEvent {
	return t.eventChan
}

func parseRawEvent(data []byte) (*model.RawTraceEvent, error) {
	if len(data) < int(unsafe.Sizeof(model.RawTraceEvent{})) {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	var event model.RawTraceEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parsing event: %w", err)
	}

	return &event, nil
}

func (t *Tracer) GetMap(name string) (*ebpf.Map, error) {
	switch name {
	case "connections":
		return t.objs.Connections, nil
	case "socket_to_conn":
		return t.objs.SocketToConn, nil
	case "events":
		return t.objs.Events, nil
	default:
		return nil, fmt.Errorf("map not found: %s", name)
	}
}
