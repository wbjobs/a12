package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../bpf/network_trace.bpf.c -- -I../bpf

type BPFStats struct {
	EventsTotal   uint64 `json:"events_total"`
	EventsDropped uint64 `json:"events_dropped"`
	EventsSent    uint64 `json:"events_sent"`
	Connections   uint64 `json:"connections"`
	RingbufDropped uint64 `json:"ringbuf_dropped"`
}

type Tracer struct {
	objs            *bpfObjects
	links           []link.Link
	ringbuf         *ringbuf.Reader
	eventChan       chan *model.RawTraceEvent
	stopChan        chan struct{}
	eventHandler    func(*model.RawTraceEvent)
	mu              sync.Mutex
	running         bool
	workers         int
	stats           atomic.Value
	processedEvents atomic.Uint64
	droppedEvents   atomic.Uint64
}

func NewTracer(cfg *config.EBPFConfig) (*Tracer, error) {
	workers := 4
	if runtime.NumCPU() > workers {
		workers = runtime.NumCPU()
	}

	t := &Tracer{
		eventChan: make(chan *model.RawTraceEvent, 100000),
		stopChan:  make(chan struct{}),
		workers:   workers,
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
			l, err = link.Kretprobe(kp.name, kp.fn.(*ebpf.Program), nil)
		} else {
			l, err = link.Kprobe(kp.name, kp.fn.(*ebpf.Program), nil)
		}

		if err != nil {
			return nil, fmt.Errorf("creating kprobe %s: %w", kp.name, err)
		}
		t.links = append(t.links, l)
		log.Printf("Attached kprobe: %s", kp.name)
	}

	reader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	t.ringbuf = reader

	go t.statsPoller()

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

	for i := 0; i < t.workers; i++ {
		go t.eventWorker(ctx, i)
	}

	go t.pollEvents(ctx)

	log.Printf("eBPF tracer started successfully with %d workers", t.workers)
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

	if t.ringbuf != nil {
		if err := t.ringbuf.Close(); err != nil {
			log.Printf("Warning: closing ringbuf reader: %v", err)
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopChan:
			return
		default:
			record, err := t.ringbuf.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				if isTemporaryError(err) {
					continue
				}
				log.Printf("Error reading ringbuf record: %v", err)
				t.droppedEvents.Add(1)
				continue
			}

			event, err := parseRawEvent(record.RawSample)
			if err != nil {
				log.Printf("Error parsing event: %v", err)
				t.droppedEvents.Add(1)
				continue
			}

			select {
			case t.eventChan <- event:
				t.processedEvents.Add(1)
			default:
				t.droppedEvents.Add(1)
				log.Printf("Warning: event channel full, dropping event")
			}
		}
	}
}

func (t *Tracer) eventWorker(ctx context.Context, id int) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopChan:
			return
		case event, ok := <-t.eventChan:
			if !ok {
				return
			}

			if t.eventHandler != nil {
				t.eventHandler(event)
			}
		}
	}
}

func (t *Tracer) Events() <-chan *model.RawTraceEvent {
	return t.eventChan
}

func (t *Tracer) GetStats() BPFStats {
	stats, _ := t.stats.Load().(BPFStats)
	stats.EventsSent = t.processedEvents.Load()
	stats.RingbufDropped = t.droppedEvents.Load()
	return stats
}

func (t *Tracer) statsPoller() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := t.readBPFStats()
		t.stats.Store(stats)

		if stats.EventsDropped > 0 {
			log.Printf("BPF Stats: total=%d, dropped=%d, sent=%d, connections=%d, channel_dropped=%d",
				stats.EventsTotal, stats.EventsDropped, stats.EventsSent,
				stats.Connections, t.droppedEvents.Load())
		}
	}
}

func (t *Tracer) readBPFStats() BPFStats {
	var stats BPFStats
	var key uint32 = 0

	var value struct {
		EventsTotal   uint64
		EventsDropped uint64
		EventsSent    uint64
		Connections   uint64
		RingbufDropped uint64
	}

	if err := t.objs.Stats.Lookup(&key, &value); err == nil {
		stats.EventsTotal = value.EventsTotal
		stats.EventsDropped = value.EventsDropped
		stats.EventsSent = value.EventsSent
	}

	if connMap, err := t.GetMap("connections"); err == nil {
		iter := connMap.Iterate()
		count := 0
		var key, val []byte
		for iter.Next(&key, &val) {
			count++
		}
		stats.Connections = uint64(count)
	}

	return stats
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
	case "stats":
		return t.objs.Stats, nil
	default:
		return nil, fmt.Errorf("map not found: %s", name)
	}
}

func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	var tempErr interface{ Temporary() bool }
	if errors.As(err, &tempErr) && tempErr.Temporary() {
		return true
	}

	var timeoutErr interface{ Timeout() bool }
	if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
		return true
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	return false
}
