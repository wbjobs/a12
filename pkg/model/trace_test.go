package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTraceID(t *testing.T) {
	traceID := GenerateTraceID()
	assert.Len(t, traceID, 32, "TraceID should be 32 hex characters")

	traceID2 := GenerateTraceID()
	assert.NotEqual(t, traceID, traceID2, "TraceIDs should be unique")
}

func TestGenerateSpanID(t *testing.T) {
	spanID := GenerateSpanID()
	assert.Len(t, spanID, 16, "SpanID should be 16 hex characters")
}

func TestConvertRawEventToSpan(t *testing.T) {
	raw := &RawTraceEvent{
		Timestamp:   uint64(time.Now().UnixNano()),
		PID:         1234,
		TID:         5678,
		EventType:   uint8(EventTypeSendTo),
		Protocol:    uint8(ProtocolHTTP),
		SAddr:       0x0100007F,
		DAddr:       0x0200007F,
		SPort:       0x5000,
		DPort:       0x901F,
		DurationNs:  150000000,
		ErrorCode:   200,
		PayloadSize: 1024,
	}

	span := ConvertRawEventToSpan(raw)

	assert.NotEmpty(t, span.TraceID)
	assert.NotEmpty(t, span.SpanID)
	assert.Equal(t, "send", span.EventType)
	assert.Equal(t, "http", span.Protocol)
	assert.Equal(t, float64(150), span.DurationMs)
	assert.Equal(t, int32(200), span.ErrorCode)
	assert.Equal(t, uint32(1024), span.PayloadSize)
	assert.Equal(t, "127.0.0.1", span.SourceIP)
	assert.Equal(t, "127.0.0.2", span.DestIP)
	assert.Equal(t, uint16(8080), span.DestPort)
}

func TestBuildTraceTree(t *testing.T) {
	now := time.Now()

	spans := []*Span{
		{
			TraceID:      "trace123",
			SpanID:       "root",
			ParentSpanID: "",
			Operation:    "GET /api",
			StartTime:    now,
			EndTime:      now.Add(300 * time.Millisecond),
			DurationMs:   300,
		},
		{
			TraceID:      "trace123",
			SpanID:       "child1",
			ParentSpanID: "root",
			Operation:    "DB Query",
			StartTime:    now.Add(50 * time.Millisecond),
			EndTime:      now.Add(150 * time.Millisecond),
			DurationMs:   100,
		},
		{
			TraceID:      "trace123",
			SpanID:       "child2",
			ParentSpanID: "root",
			Operation:    "RPC Call",
			StartTime:    now.Add(100 * time.Millisecond),
			EndTime:      now.Add(250 * time.Millisecond),
			DurationMs:   150,
		},
		{
			TraceID:      "trace123",
			SpanID:       "grandchild",
			ParentSpanID: "child2",
			Operation:    "Redis GET",
			StartTime:    now.Add(120 * time.Millisecond),
			EndTime:      now.Add(130 * time.Millisecond),
			DurationMs:   10,
		},
	}

	trace := BuildTraceTree(spans)

	assert.NotNil(t, trace)
	assert.Equal(t, "trace123", trace.TraceID)
	assert.NotNil(t, trace.RootSpan)
	assert.Equal(t, "root", trace.RootSpan.SpanID)
	assert.Len(t, trace.RootSpan.Children, 2)
	assert.Equal(t, float64(300), trace.Duration)

	var child2 *Span
	for _, child := range trace.RootSpan.Children {
		if child.SpanID == "child2" {
			child2 = child
			break
		}
	}
	assert.NotNil(t, child2)
	assert.Len(t, child2.Children, 1)
	assert.Equal(t, "grandchild", child2.Children[0].SpanID)
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventTypeConnect, "connect"},
		{EventTypeAccept, "accept"},
		{EventTypeSendTo, "send"},
		{EventTypeRecvFrom, "recv"},
		{EventTypeClose, "close"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.eventType.String())
	}
}

func TestProtocolString(t *testing.T) {
	tests := []struct {
		protocol Protocol
		expected string
	}{
		{ProtocolHTTP, "http"},
		{ProtocolGRPC, "grpc"},
		{ProtocolRedis, "redis"},
		{ProtocolUnknown, "unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.protocol.String())
	}
}

func BenchmarkGenerateTraceID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateTraceID()
	}
}

func BenchmarkConvertRawEventToSpan(b *testing.B) {
	raw := &RawTraceEvent{
		Timestamp:   uint64(time.Now().UnixNano()),
		PID:         1234,
		EventType:   uint8(EventTypeSendTo),
		Protocol:    uint8(ProtocolHTTP),
		DurationNs:  150000000,
		PayloadSize: 1024,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConvertRawEventToSpan(raw)
	}
}
