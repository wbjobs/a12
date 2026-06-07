package model

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"time"
)

type EventType uint8

const (
	EventTypeConnect  EventType = 0
	EventTypeAccept   EventType = 1
	EventTypeSendTo   EventType = 2
	EventTypeRecvFrom EventType = 3
	EventTypeClose    EventType = 4
)

func (e EventType) String() string {
	switch e {
	case EventTypeConnect:
		return "connect"
	case EventTypeAccept:
		return "accept"
	case EventTypeSendTo:
		return "send"
	case EventTypeRecvFrom:
		return "recv"
	case EventTypeClose:
		return "close"
	default:
		return "unknown"
	}
}

type Protocol uint8

const (
	ProtocolHTTP    Protocol = 0
	ProtocolGRPC    Protocol = 1
	ProtocolRedis   Protocol = 2
	ProtocolEnvoy   Protocol = 3
	ProtocolUnknown Protocol = 4
)

func (p Protocol) String() string {
	switch p {
	case ProtocolHTTP:
		return "http"
	case ProtocolGRPC:
		return "grpc"
	case ProtocolRedis:
		return "redis"
	case ProtocolEnvoy:
		return "envoy"
	default:
		return "unknown"
	}
}

type RawTraceEvent struct {
	Timestamp    uint64
	PID          uint32
	TID          uint32
	UID          uint32
	GID          uint32
	Comm         [16]byte
	EventType    uint8
	Protocol     uint8
	SAddr        uint32
	DAddr        uint32
	SPort        uint16
	DPort        uint16
	DurationNs   uint64
	ErrorCode    int32
	PayloadSize  uint32
	Payload      [1024]byte
	TraceID      [33]byte
	SpanID       [17]byte
	ParentSpanID [17]byte
	Path         [256]byte
}

type Span struct {
	TraceID      string                 `json:"traceId"`
	SpanID       string                 `json:"spanId"`
	ParentSpanID string                 `json:"parentSpanId"`
	ServiceName  string                 `json:"serviceName"`
	Operation    string                 `json:"operation"`
	Protocol     string                 `json:"protocol"`
	EventType    string                 `json:"eventType"`
	StartTime    time.Time              `json:"startTime"`
	EndTime      time.Time              `json:"endTime"`
	DurationMs   float64                `json:"durationMs"`
	ErrorCode    int32                  `json:"errorCode"`
	PayloadSize  uint32                 `json:"payloadSize"`
	Payload      string                 `json:"payload,omitempty"`
	SourceIP     string                 `json:"sourceIp"`
	DestIP       string                 `json:"destIp"`
	SourcePort   uint16                 `json:"sourcePort"`
	DestPort     uint16                 `json:"destPort"`
	PID          uint32                 `json:"pid"`
	Comm         string                 `json:"comm"`
	Path         string                 `json:"path,omitempty"`
	Children     []*Span                `json:"children,omitempty"`
	Tags         map[string]interface{} `json:"tags,omitempty"`
}

func (s *Span) SetTag(key string, value interface{}) {
	if s.Tags == nil {
		s.Tags = make(map[string]interface{})
	}
	s.Tags[key] = value
}

type Trace struct {
	TraceID   string    `json:"traceId"`
	Spans     []*Span   `json:"spans"`
	RootSpan  *Span     `json:"rootSpan"`
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime"`
	Duration  float64   `json:"durationMs"`
}

type TraceQuery struct {
	TraceID       string     `json:"traceId"`
	ServiceName   string     `json:"serviceName"`
	StartTime     *time.Time `json:"startTime"`
	EndTime       *time.Time `json:"endTime"`
	MinLatencyMs  *float64   `json:"minLatencyMs"`
	MaxLatencyMs  *float64   `json:"maxLatencyMs"`
	Protocol      string     `json:"protocol"`
	Limit         int        `json:"limit"`
	Offset        int        `json:"offset"`
}

func GenerateTraceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GenerateSpanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func intToIP(ip uint32) string {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	).String()
}

func ntohs(port uint16) uint16 {
	return (port>>8)|(port<<8)
}

func ConvertRawEventToSpan(raw *RawTraceEvent) *Span {
	span := &Span{
		TraceID:      string(raw.TraceID[:]),
		SpanID:       string(raw.SpanID[:]),
		ParentSpanID: string(raw.ParentSpanID[:]),
		ServiceName:  string(raw.Comm[:]),
		Operation:    EventType(raw.EventType).String(),
		Protocol:     Protocol(raw.Protocol).String(),
		EventType:    EventType(raw.EventType).String(),
		StartTime:    time.Unix(0, int64(raw.Timestamp)),
		ErrorCode:    raw.ErrorCode,
		PayloadSize:  raw.PayloadSize,
		Payload:      string(raw.Payload[:]),
		SourceIP:     intToIP(raw.SAddr),
		DestIP:       intToIP(raw.DAddr),
		SourcePort:   ntohs(raw.SPort),
		DestPort:     ntohs(raw.DPort),
		PID:          raw.PID,
		Comm:         string(raw.Comm[:]),
		Path:         string(raw.Path[:]),
	}
	
	if span.TraceID == "" {
		span.TraceID = GenerateTraceID()
	}
	if span.SpanID == "" {
		span.SpanID = GenerateSpanID()
	}
	
	span.DurationMs = float64(raw.DurationNs) / 1e6
	span.EndTime = span.StartTime.Add(time.Duration(raw.DurationNs))
	
	return span
}

func BuildTraceTree(spans []*Span) *Trace {
	if len(spans) == 0 {
		return nil
	}
	
	spanMap := make(map[string]*Span)
	var root *Span
	
	for _, span := range spans {
		spanMap[span.SpanID] = span
		if span.ParentSpanID == "" {
			root = span
		}
	}
	
	for _, span := range spans {
		if span.ParentSpanID != "" {
			if parent, ok := spanMap[span.ParentSpanID]; ok {
				parent.Children = append(parent.Children, span)
			}
		}
	}
	
	trace := &Trace{
		TraceID:  spans[0].TraceID,
		Spans:    spans,
		RootSpan: root,
	}
	
	if len(spans) > 0 {
		trace.StartTime = spans[0].StartTime
		trace.EndTime = spans[0].EndTime
		for _, span := range spans {
			if span.StartTime.Before(trace.StartTime) {
				trace.StartTime = span.StartTime
			}
			if span.EndTime.After(trace.EndTime) {
				trace.EndTime = span.EndTime
			}
		}
		trace.Duration = float64(trace.EndTime.Sub(trace.StartTime).Nanoseconds()) / 1e6
	}
	
	return trace
}

func (s *Span) String() string {
	return fmt.Sprintf("Span[trace=%s, span=%s, parent=%s, op=%s, dur=%.2fms]",
		s.TraceID, s.SpanID, s.ParentSpanID, s.Operation, s.DurationMs)
}
