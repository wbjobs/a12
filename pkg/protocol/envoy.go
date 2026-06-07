package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

const (
	EnvoyProxyMagic    uint64 = 0x0000000000000000
	EnvoyHeaderLen     int    = 28
	EnvoyMaxMessageLen int    = 1024 * 1024 * 16
)

type EnvoyMessageType uint8

const (
	EnvoyTypeData       EnvoyMessageType = 0x01
	EnvoyTypeHandshake  EnvoyMessageType = 0x02
	EnvoyTypeAck        EnvoyMessageType = 0x03
	EnvoyTypeKeepalive  EnvoyMessageType = 0x04
	EnvoyTypeReset      EnvoyMessageType = 0x05
)

type EnvoyHeader struct {
	Magic         uint32
	Version       uint8
	Type          EnvoyMessageType
	Flags         uint8
	StreamID      uint64
	Length        uint32
	Timestamp     uint64
	Checksum      uint32
}

type EnvoyMessage struct {
	Header     *EnvoyHeader
	Payload    []byte
	Protocol   string
	IsRequest  bool
	IsUDP      bool
}

type EnvoyParser struct {
	knownPorts map[uint16]bool
}

func NewEnvoyParser() *EnvoyParser {
	return &EnvoyParser{
		knownPorts: map[uint16]bool{
			15001: true,
			15006: true,
			15010: true,
			15011: true,
			15012: true,
			15014: true,
			15017: true,
			15018: true,
			15021: true,
			15020: true,
			15090: true,
			15051: true,
		},
	}
}

func (p *EnvoyParser) CanHandle(port uint16, payload []byte) bool {
	if p.knownPorts[port] {
		return true
	}

	if len(payload) < 8 {
		return false
	}

	magic := binary.BigEndian.Uint32(payload[0:4])
	version := payload[4]
	msgType := payload[5]

	if magic == 0x454E5659 && version <= 2 && msgType <= 5 {
		return true
	}

	if len(payload) > 12 {
		streamID := binary.BigEndian.Uint64(payload[8:16])
		length := binary.BigEndian.Uint32(payload[16:20])
		if streamID > 0 && length > 0 && length < uint32(EnvoyMaxMessageLen) {
			return true
		}
	}

	if len(payload) > 4 {
		first4 := payload[:4]
		if first4[0] == 0x45 && first4[1] == 0x4E && first4[2] == 0x56 && first4[3] == 0x59 {
			return true
		}
	}

	return false
}

func (p *EnvoyParser) Parse(payload []byte, span *model.Span) (*EnvoyMessage, error) {
	if len(payload) < EnvoyHeaderLen {
		return nil, fmt.Errorf("payload too small for Envoy header: %d bytes", len(payload))
	}

	header, err := p.parseHeader(payload)
	if err != nil {
		return nil, err
	}

	msg := &EnvoyMessage{
		Header: header,
		IsUDP:  (header.Flags & 0x01) != 0,
	}

	if header.Length > 0 {
		payloadStart := EnvoyHeaderLen
		payloadEnd := payloadStart + int(header.Length)
		if payloadEnd > len(payload) {
			payloadEnd = len(payload)
		}
		msg.Payload = payload[payloadStart:payloadEnd]
	}

	msg.Protocol = p.detectInnerProtocol(msg.Payload)
	msg.IsRequest = p.isRequest(header, msg.Payload)

	if span != nil {
		span.SetTag("envoy_stream_id", header.StreamID)
		span.SetTag("envoy_type", p.messageTypeString(header.Type))
		span.SetTag("envoy_version", header.Version)
		span.SetTag("envoy_udp", msg.IsUDP)
		span.SetTag("envoy_length", header.Length)
		span.SetTag("envoy_flags", header.Flags)

		if msg.Protocol != "" {
			span.SetTag("inner_protocol", msg.Protocol)
		}

		span.Operation = fmt.Sprintf("ENVOY_%s_%s",
			strings.ToUpper(p.messageTypeString(header.Type)),
			strings.ToUpper(msg.Protocol))

		if msg.IsUDP {
			span.ServiceName += "-sidecar"
		}
	}

	return msg, nil
}

func (p *EnvoyParser) parseHeader(payload []byte) (*EnvoyHeader, error) {
	if len(payload) < EnvoyHeaderLen {
		return nil, fmt.Errorf("invalid header size")
	}

	header := &EnvoyHeader{
		Magic:     binary.BigEndian.Uint32(payload[0:4]),
		Version:   payload[4],
		Type:      EnvoyMessageType(payload[5]),
		Flags:     payload[6],
		StreamID:  binary.BigEndian.Uint64(payload[8:16]),
		Length:    binary.BigEndian.Uint32(payload[16:20]),
		Timestamp: binary.BigEndian.Uint64(payload[20:28]),
	}

	if len(payload) >= 32 {
		header.Checksum = binary.BigEndian.Uint32(payload[28:32])
	}

	if header.Magic != 0x454E5659 {
		return header, fmt.Errorf("invalid Envoy magic: 0x%x", header.Magic)
	}

	if header.Length > uint32(EnvoyMaxMessageLen) {
		return header, fmt.Errorf("message too large: %d bytes", header.Length)
	}

	return header, nil
}

func (p *EnvoyParser) detectInnerProtocol(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	if len(payload) > 4 {
		if payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ' {
			return "http"
		}
		if payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' {
			return "http"
		}
		if payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P' {
			return "http"
		}
	}

	if len(payload) > 5 {
		if payload[0] == 0x50 && payload[1] == 0x52 && payload[2] == 0x49 {
			return "redis"
		}
	}

	if len(payload) > 8 {
		grpcMagic := binary.BigEndian.Uint32(payload[0:4])
		if grpcMagic&0x000000FF == 0x00 || grpcMagic&0x000000FF == 0x01 {
			length := binary.BigEndian.Uint32(payload[1:5])
			if length > 0 && length < 1024*1024 {
				return "grpc"
			}
		}
	}

	if len(payload) > 2 && (payload[0] == 0x01 || payload[0] == 0x02) {
		if payload[1] == 0x01 || payload[1] == 0x02 {
			return "mysql"
		}
	}

	return "unknown"
}

func (p *EnvoyParser) isRequest(header *EnvoyHeader, payload []byte) bool {
	if header.Flags&0x02 != 0 {
		return false
	}

	if len(payload) > 4 {
		if payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' {
			return true
		}
		if payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' {
			return true
		}
		if payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' {
			return true
		}
		if payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' {
			return true
		}
		if payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P' {
			return false
		}
	}

	return header.Type == EnvoyTypeData
}

func (p *EnvoyParser) messageTypeString(t EnvoyMessageType) string {
	switch t {
	case EnvoyTypeData:
		return "DATA"
	case EnvoyTypeHandshake:
		return "HANDSHAKE"
	case EnvoyTypeAck:
		return "ACK"
	case EnvoyTypeKeepalive:
		return "KEEPALIVE"
	case EnvoyTypeReset:
		return "RESET"
	default:
		return fmt.Sprintf("UNKNOWN_%d", t)
	}
}

func (p *EnvoyParser) ParseMultiple(payload []byte) ([]*EnvoyMessage, error) {
	var messages []*EnvoyMessage
	pos := 0

	for pos < len(payload) {
		remaining := len(payload) - pos
		if remaining < EnvoyHeaderLen {
			break
		}

		header, err := p.parseHeader(payload[pos:])
		if err != nil {
			break
		}

		msgLen := EnvoyHeaderLen + int(header.Length)
		if pos+msgLen > len(payload) {
			break
		}

		msg, err := p.Parse(payload[pos:pos+msgLen], nil)
		if err != nil {
			pos++
			continue
		}

		messages = append(messages, msg)
		pos += msgLen
	}

	return messages, nil
}

func (p *EnvoyParser) ExtractInnerPayload(envoyPayload []byte) []byte {
	if len(envoyPayload) < EnvoyHeaderLen {
		return envoyPayload
	}

	header, err := p.parseHeader(envoyPayload)
	if err != nil {
		return envoyPayload
	}

	payloadStart := EnvoyHeaderLen
	payloadEnd := payloadStart + int(header.Length)
	if payloadEnd > len(envoyPayload) {
		payloadEnd = len(envoyPayload)
	}

	return envoyPayload[payloadStart:payloadEnd]
}
