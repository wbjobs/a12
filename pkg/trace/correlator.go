package trace

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
	"github.com/ebpf-tracing/ebpf-apm/pkg/protocol"
)

type PendingRequest struct {
	Span       *model.Span
	RawEvent   *model.RawTraceEvent
	ProtocolInfo *protocol.ProtocolInfo
	Timestamp  time.Time
}

type ConnectionFlow struct {
	PID         uint32
	SourceIP    string
	DestIP      string
	SourcePort  uint16
	DestPort    uint16
	LastSend    time.Time
	LastRecv    time.Time
	RequestSpan *model.Span
}

type Correlator struct {
	pendingRequests *list.List
	pendingMutex    sync.Mutex
	connections     map[string]*ConnectionFlow
	connMutex       sync.RWMutex
	parser          *protocol.Parser
	timeout         time.Duration
	spanHandler     func(*model.Span)
}

func NewCorrelator() *Correlator {
	c := &Correlator{
		pendingRequests: list.New(),
		connections:     make(map[string]*ConnectionFlow),
		parser:          protocol.NewParser(),
		timeout:         30 * time.Second,
	}

	go c.cleanupLoop()
	return c
}

func (c *Correlator) SetSpanHandler(handler func(*model.Span)) {
	c.spanHandler = handler
}

func (c *Correlator) ProcessEvent(event *model.RawTraceEvent) {
	span := model.ConvertRawEventToSpan(event)
	protoInfo := c.parser.Parse(event, span)

	_ = protoInfo

	connKey := getConnectionKey(span.PID, span.SourceIP, span.DestIP, span.SourcePort, span.DestPort)

	switch model.EventType(event.EventType) {
	case model.EventTypeConnect:
		c.handleConnect(span, event)
	case model.EventTypeAccept:
		c.handleAccept(span, event)
	case model.EventTypeSendTo:
		c.handleSend(span, event, connKey)
	case model.EventTypeRecvFrom:
		c.handleRecv(span, event, connKey)
	case model.EventTypeClose:
		c.handleClose(span, event, connKey)
	}

	if span.TraceID != "" && c.spanHandler != nil {
		c.spanHandler(span)
	}

	if span.TraceID == "" {
		c.pendingMutex.Lock()
		c.pendingRequests.PushBack(&PendingRequest{
			Span:      span,
			RawEvent:  event,
			Timestamp: time.Now(),
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
		PID:        span.PID,
		SourceIP:   span.SourceIP,
		DestIP:     span.DestIP,
		SourcePort: span.SourcePort,
		DestPort:   span.DestPort,
	}
	
	log.Printf("New connection: %s -> %s:%d (pid=%d)",
		span.SourceIP, span.DestIP, span.DestPort, span.PID)
}

func (c *Correlator) handleAccept(span *model.Span, event *model.RawTraceEvent) {
	connKey := getConnectionKey(span.PID, span.SourceIP, span.DestIP, span.SourcePort, span.DestPort)
	
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	
	c.connections[connKey] = &ConnectionFlow{
		PID:        span.PID,
		SourceIP:   span.SourceIP,
		DestIP:     span.DestIP,
		SourcePort: span.SourcePort,
		DestPort:   span.DestPort,
	}
	
	log.Printf("Accepted connection: %s:%d -> %s (pid=%d)",
		span.SourceIP, span.SourcePort, span.DestIP, span.PID)
}

func (c *Correlator) handleSend(span *model.Span, event *model.RawTraceEvent, connKey string) {
	c.connMutex.RLock()
	flow, exists := c.connections[connKey]
	c.connMutex.RUnlock()
	
	if !exists {
		flow = c.createFlow(span, connKey)
	}
	
	flow.LastSend = time.Now()
	
	if isRequestPayload(event) {
		if span.TraceID == "" {
			span.TraceID = generateDeterministicTraceID(span)
			span.SpanID = model.GenerateSpanID()
		}
		flow.RequestSpan = span
	}
}

func (c *Correlator) handleRecv(span *model.Span, event *model.RawTraceEvent, connKey string) {
	c.connMutex.RLock()
	flow, exists := c.connections[connKey]
	c.connMutex.RUnlock()
	
	if !exists {
		flow = c.createFlow(span, connKey)
	}
	
	flow.LastRecv = time.Now()
	
	if flow.RequestSpan != nil && isResponsePayload(event) {
		span.ParentSpanID = flow.RequestSpan.SpanID
		span.TraceID = flow.RequestSpan.TraceID
		span.SpanID = model.GenerateSpanID()
		
		duration := float64(time.Since(flow.RequestSpan.StartTime).Nanoseconds()) / 1e6
		span.DurationMs = duration
		
		flow.RequestSpan = nil
	}
}

func (c *Correlator) handleClose(span *model.Span, event *model.RawTraceEvent, connKey string) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	
	if flow, exists := c.connections[connKey]; exists {
		if flow.RequestSpan != nil && c.spanHandler != nil {
			c.spanHandler(flow.RequestSpan)
		}
		delete(c.connections, connKey)
	}
	
	log.Printf("Connection closed: %s:%d <-> %s:%d",
		span.SourceIP, span.SourcePort, span.DestIP, span.DestPort)
}

func (c *Correlator) createFlow(span *model.Span, connKey string) *ConnectionFlow {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	
	flow := &ConnectionFlow{
		PID:        span.PID,
		SourceIP:   span.SourceIP,
		DestIP:     span.DestIP,
		SourcePort: span.SourcePort,
		DestPort:   span.DestPort,
	}
	c.connections[connKey] = flow
	return flow
}

func (c *Correlator) tryCorrelate(span *model.Span, event *model.RawTraceEvent, connKey string) {
	c.connMutex.RLock()
	flow, exists := c.connections[connKey]
	c.connMutex.RUnlock()
	
	if !exists {
		return
	}
	
	if flow.RequestSpan != nil && event.EventType == uint8(model.EventTypeRecvFrom) {
		span.ParentSpanID = flow.RequestSpan.SpanID
		span.TraceID = flow.RequestSpan.TraceID
		span.SpanID = model.GenerateSpanID()
		
		if c.spanHandler != nil {
			c.spanHandler(flow.RequestSpan)
			c.spanHandler(span)
		}
		
		flow.RequestSpan = nil
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
			if c.spanHandler != nil {
				c.spanHandler(req.Span)
			}
			c.pendingRequests.Remove(e)
		}
		e = next
	}
	c.pendingMutex.Unlock()
	
	c.connMutex.Lock()
	for key, flow := range c.connections {
		if now.Sub(flow.LastSend) > c.timeout && now.Sub(flow.LastRecv) > c.timeout {
			if flow.RequestSpan != nil && c.spanHandler != nil {
				c.spanHandler(flow.RequestSpan)
			}
			delete(c.connections, key)
		}
	}
	c.connMutex.Unlock()
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
