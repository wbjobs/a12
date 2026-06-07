package trace

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
	"github.com/ebpf-tracing/ebpf-apm/pkg/protocol"
)

type PendingRequest struct {
	Span         *model.Span
	RawEvent     *model.RawTraceEvent
	ProtocolInfo *protocol.ProtocolInfo
	Timestamp    time.Time
}

type inflightRequest struct {
	span       *model.Span
	event      *model.RawTraceEvent
	protoInfo  *protocol.ProtocolInfo
	sendTime   time.Time
	seq        uint64
}

type ConnectionFlow struct {
	PID            uint32
	SourceIP       string
	DestIP         string
	SourcePort     uint16
	DestPort       uint16
	LastSend       time.Time
	LastRecv       time.Time
	inflightReqs   *list.List
	inflightMutex  sync.Mutex
	seqCounter     uint64
}

type CorrelatorStats struct {
	TotalEvents      uint64 `json:"total_events"`
	ProcessedSpans   uint64 `json:"processed_spans"`
	DroppedEvents    uint64 `json:"dropped_events"`
	InflightRequests uint64 `json:"inflight_requests"`
	ActiveConnections uint64 `json:"active_connections"`
}

type Correlator struct {
	pendingRequests *list.List
	pendingMutex    sync.Mutex
	connections     map[string]*ConnectionFlow
	connMutex       sync.RWMutex
	parser          *protocol.Parser
	timeout         time.Duration
	maxInflight     int
	spanHandler     func(*model.Span)
	stats           CorrelatorStats
}

func NewCorrelator() *Correlator {
	c := &Correlator{
		pendingRequests: list.New(),
		connections:     make(map[string]*ConnectionFlow),
		parser:          protocol.NewParser(),
		timeout:         30 * time.Second,
		maxInflight:     1000,
	}

	go c.cleanupLoop()
	go c.statsReporter()
	return c
}

func (c *Correlator) SetSpanHandler(handler func(*model.Span)) {
	c.spanHandler = handler
}

func (c *Correlator) ProcessEvent(event *model.RawTraceEvent) {
	atomic.AddUint64(&c.stats.TotalEvents, 1)

	span := model.ConvertRawEventToSpan(event)
	protoInfo := c.parser.Parse(event, span)

	connKey := getConnectionKey(span.PID, span.SourceIP, span.DestIP, span.SourcePort, span.DestPort)

	switch model.EventType(event.EventType) {
	case model.EventTypeConnect:
		c.handleConnect(span, event)
	case model.EventTypeAccept:
		c.handleAccept(span, event)
	case model.EventTypeSendTo:
		c.handleSend(span, event, connKey, protoInfo)
	case model.EventTypeRecvFrom:
		c.handleRecv(span, event, connKey, protoInfo)
	case model.EventTypeClose:
		c.handleClose(span, event, connKey)
	}

	if span.TraceID != "" && c.spanHandler != nil {
		c.spanHandler(span)
		atomic.AddUint64(&c.stats.ProcessedSpans, 1)
		return
	}

	if span.TraceID == "" {
		c.pendingMutex.Lock()
		c.pendingRequests.PushBack(&PendingRequest{
			Span:       span,
			RawEvent:   event,
			Timestamp:  time.Now(),
		})
		c.pendingMutex.Unlock()

		c.tryCorrelate(span, event, connKey)
	}
}

func (c *Correlator) handleConnect(span *model.Span, event *model.RawTraceEvent) {
	connKey := getConnectionKey(span.PID, span.SourceIP, span.DestIP, span.SourcePort, span.DestPort)

	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	c.connections[connKey] = &ConnectionFlow{
		PID:          span.PID,
		SourceIP:     span.SourceIP,
		DestIP:       span.DestIP,
		SourcePort:   span.SourcePort,
		DestPort:     span.DestPort,
		inflightReqs: list.New(),
	}

	atomic.AddUint64(&c.stats.ActiveConnections, 1)
	log.Printf("New connection: %s -> %s:%d (pid=%d)",
		span.SourceIP, span.DestIP, span.DestPort, span.PID)
}

func (c *Correlator) handleAccept(span *model.Span, event *model.RawTraceEvent) {
	connKey := getConnectionKey(span.PID, span.SourceIP, span.DestIP, span.SourcePort, span.DestPort)

	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	c.connections[connKey] = &ConnectionFlow{
		PID:          span.PID,
		SourceIP:     span.SourceIP,
		DestIP:       span.DestIP,
		SourcePort:   span.SourcePort,
		DestPort:     span.DestPort,
		inflightReqs: list.New(),
	}

	atomic.AddUint64(&c.stats.ActiveConnections, 1)
	log.Printf("Accepted connection: %s:%d -> %s (pid=%d)",
		span.SourceIP, span.SourcePort, span.DestIP, span.PID)
}

func (c *Correlator) handleSend(span *model.Span, event *model.RawTraceEvent, connKey string, protoInfo *protocol.ProtocolInfo) {
	flow := c.getOrCreateFlow(span, connKey)
	flow.LastSend = time.Now()

	if isRequestPayload(event) {
		if span.TraceID == "" {
			span.TraceID = generateDeterministicTraceID(span)
			span.SpanID = model.GenerateSpanID()
		}

		flow.inflightMutex.Lock()
		if flow.inflightReqs.Len() >= c.maxInflight {
			oldest := flow.inflightReqs.Front()
			if oldest != nil {
				req := oldest.Value.(*inflightRequest)
				log.Printf("Warning: inflight queue full for %s, dropping oldest request seq=%d",
					connKey, req.seq)
				flow.inflightReqs.Remove(oldest)
				atomic.AddUint64(&c.stats.DroppedEvents, 1)

				if c.spanHandler != nil {
					c.spanHandler(req.span)
					atomic.AddUint64(&c.stats.ProcessedSpans, 1)
				}
			}
		}

		seq := atomic.AddUint64(&flow.seqCounter, 1)
		flow.inflightReqs.PushBack(&inflightRequest{
			span:      span,
			event:     event,
			protoInfo: protoInfo,
			sendTime:  time.Now(),
			seq:       seq,
		})
		flow.inflightMutex.Unlock()

		atomic.AddUint64(&c.stats.InflightRequests, 1)

		span.SetTag("request_seq", seq)
	}
}

func (c *Correlator) handleRecv(span *model.Span, event *model.RawTraceEvent, connKey string, protoInfo *protocol.ProtocolInfo) {
	flow := c.getOrCreateFlow(span, connKey)
	flow.LastRecv = time.Now()

	if isResponsePayload(event) {
		flow.inflightMutex.Lock()
		front := flow.inflightReqs.Front()
		flow.inflightMutex.Unlock()

		if front != nil {
			flow.inflightMutex.Lock()
			front = flow.inflightReqs.Front()
			if front != nil {
				req := front.Value.(*inflightRequest)
				flow.inflightReqs.Remove(front)
				flow.inflightMutex.Unlock()

				span.ParentSpanID = req.span.SpanID
				span.TraceID = req.span.TraceID
				span.SpanID = model.GenerateSpanID()

				duration := float64(time.Since(req.sendTime).Nanoseconds()) / 1e6
				span.DurationMs = duration
				req.span.DurationMs = duration

				span.SetTag("request_seq", req.seq)
				req.span.SetTag("response_seq", req.seq)

				atomic.AddUint64(&c.stats.InflightRequests, ^uint64(0))

				if c.spanHandler != nil {
					c.spanHandler(req.span)
					c.spanHandler(span)
					atomic.AddUint64(&c.stats.ProcessedSpans, 2)
				}

				span.SetTag("matched", true)
				return
			} else {
				flow.inflightMutex.Unlock()
			}
		}

		if span.TraceID == "" {
			span.TraceID = generateDeterministicTraceID(span)
			span.SpanID = model.GenerateSpanID()
		}
		span.SetTag("orphan_response", true)
	}
}

func (c *Correlator) handleClose(span *model.Span, event *model.RawTraceEvent, connKey string) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if flow, exists := c.connections[connKey]; exists {
		flow.inflightMutex.Lock()
		inflightCount := flow.inflightReqs.Len()
		for e := flow.inflightReqs.Front(); e != nil; e = e.Next() {
			req := e.Value.(*inflightRequest)
			if c.spanHandler != nil {
				req.span.SetTag("connection_closed", true)
				c.spanHandler(req.span)
				atomic.AddUint64(&c.stats.ProcessedSpans, 1)
			}
		}
		flow.inflightMutex.Unlock()

		atomic.AddUint64(&c.stats.InflightRequests, ^uint64(inflightCount-1))
		atomic.AddUint64(&c.stats.ActiveConnections, ^uint64(0))

		delete(c.connections, connKey)
	}

	log.Printf("Connection closed: %s:%d <-> %s:%d",
		span.SourceIP, span.SourcePort, span.DestIP, span.DestPort)
}

func (c *Correlator) getOrCreateFlow(span *model.Span, connKey string) *ConnectionFlow {
	c.connMutex.RLock()
	flow, exists := c.connections[connKey]
	c.connMutex.RUnlock()

	if !exists {
		c.connMutex.Lock()
		defer c.connMutex.Unlock()

		if flow, exists = c.connections[connKey]; !exists {
			flow = &ConnectionFlow{
				PID:          span.PID,
				SourceIP:     span.SourceIP,
				DestIP:       span.DestIP,
				SourcePort:   span.SourcePort,
				DestPort:     span.DestPort,
				inflightReqs: list.New(),
			}
			c.connections[connKey] = flow
			atomic.AddUint64(&c.stats.ActiveConnections, 1)
		}
	}

	return flow
}

func (c *Correlator) tryCorrelate(span *model.Span, event *model.RawTraceEvent, connKey string) {
	flow := c.getOrCreateFlow(span, connKey)

	if event.EventType == uint8(model.EventTypeRecvFrom) {
		flow.inflightMutex.Lock()
		front := flow.inflightReqs.Front()
		flow.inflightMutex.Unlock()

		if front != nil {
			flow.inflightMutex.Lock()
			front = flow.inflightReqs.Front()
			if front != nil {
				req := front.Value.(*inflightRequest)
				flow.inflightReqs.Remove(front)
				flow.inflightMutex.Unlock()

				span.ParentSpanID = req.span.SpanID
				span.TraceID = req.span.TraceID
				span.SpanID = model.GenerateSpanID()

				duration := float64(time.Since(req.sendTime).Nanoseconds()) / 1e6
				span.DurationMs = duration
				req.span.DurationMs = duration

				atomic.AddUint64(&c.stats.InflightRequests, ^uint64(0))

				if c.spanHandler != nil {
					c.spanHandler(req.span)
					c.spanHandler(span)
					atomic.AddUint64(&c.stats.ProcessedSpans, 2)
				}

				c.removeFromPending(req.span)
				c.removeFromPending(span)
			} else {
				flow.inflightMutex.Unlock()
			}
		}
	}
}

func (c *Correlator) removeFromPending(span *model.Span) {
	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()

	for e := c.pendingRequests.Front(); e != nil; {
		next := e.Next()
		req := e.Value.(*PendingRequest)
		if req.Span == span {
			c.pendingRequests.Remove(e)
			break
		}
		e = next
	}
}

func (c *Correlator) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanupExpired()
	}
}

func (c *Correlator) cleanupExpired() {
	now := time.Now()

	c.pendingMutex.Lock()
	for e := c.pendingRequests.Front(); e != nil; {
		next := e.Next()
		req := e.Value.(*PendingRequest)
		if now.Sub(req.Timestamp) > c.timeout {
			if req.Span.TraceID == "" {
				req.Span.TraceID = generateDeterministicTraceID(req.Span)
				req.Span.SpanID = model.GenerateSpanID()
			}
			req.Span.SetTag("timeout", true)
			if c.spanHandler != nil {
				c.spanHandler(req.Span)
				atomic.AddUint64(&c.stats.ProcessedSpans, 1)
			}
			c.pendingRequests.Remove(e)
		}
		e = next
	}
	c.pendingMutex.Unlock()

	c.connMutex.Lock()
	for key, flow := range c.connections {
		if now.Sub(flow.LastSend) > c.timeout && now.Sub(flow.LastRecv) > c.timeout {
			flow.inflightMutex.Lock()
			for e := flow.inflightReqs.Front(); e != nil; e = e.Next() {
				req := e.Value.(*inflightRequest)
				req.span.SetTag("connection_timeout", true)
				if c.spanHandler != nil {
					c.spanHandler(req.span)
					atomic.AddUint64(&c.stats.ProcessedSpans, 1)
				}
			}
			inflightCount := flow.inflightReqs.Len()
			flow.inflightMutex.Unlock()

			atomic.AddUint64(&c.stats.InflightRequests, ^uint64(inflightCount-1))
			atomic.AddUint64(&c.stats.ActiveConnections, ^uint64(0))

			delete(c.connections, key)
		}
	}
	c.connMutex.Unlock()
}

func (c *Correlator) statsReporter() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := c.GetStats()
		if stats.TotalEvents > 0 {
			log.Printf("Correlator Stats: total=%d, processed=%d, dropped=%d, inflight=%d, connections=%d",
				stats.TotalEvents, stats.ProcessedSpans, stats.DroppedEvents,
				stats.InflightRequests, stats.ActiveConnections)
		}
	}
}

func (c *Correlator) GetStats() CorrelatorStats {
	return CorrelatorStats{
		TotalEvents:       atomic.LoadUint64(&c.stats.TotalEvents),
		ProcessedSpans:    atomic.LoadUint64(&c.stats.ProcessedSpans),
		DroppedEvents:     atomic.LoadUint64(&c.stats.DroppedEvents),
		InflightRequests:  atomic.LoadUint64(&c.stats.InflightRequests),
		ActiveConnections: atomic.LoadUint64(&c.stats.ActiveConnections),
	}
}

func getConnectionKey(pid uint32, srcIP, dstIP string, srcPort, dstPort uint16) string {
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	return fmt.Sprintf("%d:%s:%d:%s:%d", pid, srcIP, srcPort, dstIP, dstPort)
}

func isRequestPayload(event *model.RawTraceEvent) bool {
	if event.PayloadSize < 4 {
		return false
	}
	payload := event.Payload[:4]
	return (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') ||
		(payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
		(payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T') ||
		(payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') ||
		(event.Protocol == uint8(model.ProtocolRedis) && payload[0] == '*') ||
		(event.Protocol == uint8(model.ProtocolGRPC) && payload[0] == 0)
}

func isResponsePayload(event *model.RawTraceEvent) bool {
	if event.PayloadSize < 4 {
		return false
	}
	payload := event.Payload[:4]
	return (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') ||
		(event.Protocol == uint8(model.ProtocolRedis) && (payload[0] == '+' || payload[0] == '-' || payload[0] == ':' || payload[0] == '$')) ||
		(event.Protocol == uint8(model.ProtocolGRPC) && payload[0] == 1)
}

func generateDeterministicTraceID(span *model.Span) string {
	data := fmt.Sprintf("%d:%s:%d:%s:%d:%d:%s",
		span.PID, span.SourceIP, span.SourcePort,
		span.DestIP, span.DestPort,
		span.StartTime.UnixNano(),
		span.Comm)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}
