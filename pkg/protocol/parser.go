package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

type ProtocolParser interface {
	Parse(payload []byte, span *model.Span) error
	CanHandle(port uint16, payload []byte) bool
}

type HTTPRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Version string            `json:"version"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type HTTPResponse struct {
	StatusCode int               `json:"statusCode"`
	Version    string            `json:"version"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
}

type GRPCMessage struct {
	ServiceName string                 `json:"serviceName"`
	MethodName  string                 `json:"methodName"`
	StatusCode  uint32                 `json:"statusCode"`
	Metadata  map[string]string      `json:"metadata"`
}

type RedisCommand struct {
	Command string   `json:"command"`
	Key     string   `json:"key"`
	Args    []string `json:"args"`
	IsResponse bool `json:"isResponse"`
}

type ProtocolInfo struct {
	HTTP   *HTTPRequest  `json:"http,omitempty"`
	GRPC   *GRPCMessage `json:"grpc,omitempty"`
	Redis  *RedisCommand `json:"redis,omitempty"`
	Raw     string       `json:"raw,omitempty"`
}

type Parser struct {
	httpParser  *HTTPParser
	grpcParser  *GRPCParser
	redisParser *RedisParser
}

func NewParser() *Parser {
	return &Parser{
		httpParser:  NewHTTPParser(),
		grpcParser:  NewGRPCParser(),
		redisParser: NewRedisParser(),
	}
}

func (p *Parser) Parse(event *model.RawTraceEvent, span *model.Span) *ProtocolInfo {
	if event.PayloadSize == 0 {
		return nil
	}

	payload := event.Payload[:event.PayloadSize]
	port := event.DPort
	if port == 0 {
		port = event.SPort
	}

	info := &ProtocolInfo{}

	switch model.Protocol(event.Protocol) {
	case model.ProtocolHTTP:
		if p.httpParser.CanHandle(port, payload) {
			if req, resp, err := p.httpParser.Parse(payload, span); err == nil {
				if req != nil {
					info.HTTP = req
					if span.Path == "" {
						span.Path = req.Path
					}
					span.Operation = req.Method + " " + req.Path
				}
				if resp != nil {
					span.ErrorCode = int32(resp.StatusCode)
				}
			}
		}
	case model.ProtocolGRPC:
		if p.grpcParser.CanHandle(port, payload) {
			if msg, err := p.grpcParser.Parse(payload, span); err == nil {
				info.GRPC = msg
				span.Operation = fmt.Sprintf("%s/%s", msg.ServiceName, msg.MethodName)
				span.ErrorCode = int32(msg.StatusCode)
			}
		}
	case model.ProtocolRedis:
		if p.redisParser.CanHandle(port, payload) {
			if cmd, err := p.redisParser.Parse(payload, span); err == nil {
				info.Redis = cmd
				span.Operation = cmd.Command + " " + cmd.Key
			}
		}
	}

	info.Raw = truncateString(string(payload), 512)
	return info
}

type HTTPParser struct {
	requestRegex  *regexp.Regexp
	responseRegex *regexp.Regexp
}

func NewHTTPParser() *HTTPParser {
	return &HTTPParser{
		requestRegex:  regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d+\.\d+)`),
		responseRegex: regexp.MustCompile(`^HTTP/(\d+\.\d+)\s+(\d+)\s+(.+)`),
	}
}

func (p *HTTPParser) CanHandle(port uint16, payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	methods := []string{"GET ", "POST", "PUT ", "DELE", "PATC", "HEAD", "OPTI", "CONN", "TRAC", "HTTP"}
	for _, m := range methods {
		if bytes.HasPrefix(payload, []byte(m)) {
			return true
		}
	}
	return false
}

func (p *HTTPParser) Parse(payload []byte, span *model.Span) (*HTTPRequest, *HTTPResponse, error) {
	if len(payload) == 0 {
		return nil, nil, fmt.Errorf("empty payload")
	}

	lines := strings.Split(string(payload), "\r\n")
	if len(lines) == 0 {
		return nil, nil, fmt.Errorf("invalid HTTP message")
	}

	firstLine := lines[0]

	if match := p.requestRegex.FindStringSubmatch(firstLine); match != nil {
		req := &HTTPRequest{
			Method:  match[1],
			Path:    match[2],
			Version: match[3],
			Headers: make(map[string]string),
		}

		for i := 1; i < len(lines); i++ {
			line := lines[i]
			if line == "" {
				break
			}
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				req.Headers[parts[0]] = parts[1]
				if strings.ToLower(parts[0]) == "x-trace-id" {
					span.TraceID = parts[1]
				}
				if strings.ToLower(parts[0]) == "x-span-id" {
					span.SpanID = parts[1]
				}
				if strings.ToLower(parts[0]) == "x-parent-span-id" {
					span.ParentSpanID = parts[1]
				}
			}
		}

		if i := strings.Index(string(payload), "\r\n\r\n"); i > 0 && i+4 < len(payload) {
			req.Body = string(payload[i+4:])
		}

		return req, nil, nil
	}

	if match := p.responseRegex.FindStringSubmatch(firstLine); match != nil {
		resp := &HTTPResponse{
			Version: match[1],
		}
		if code, err := strconv.Atoi(match[2]); err == nil {
			resp.StatusCode = code
		}
		resp.Headers = make(map[string]string)

		for i := 1; i < len(lines); i++ {
			line := lines[i]
			if line == "" {
				break
			}
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				resp.Headers[parts[0]] = parts[1]
				if strings.ToLower(parts[0]) == "x-trace-id" {
					span.TraceID = parts[1]
				}
				if strings.ToLower(parts[0]) == "x-span-id" {
					span.SpanID = parts[1]
				}
				if strings.ToLower(parts[0]) == "x-parent-span-id" {
					span.ParentSpanID = parts[1]
				}
			}
		}

		if i := strings.Index(string(payload), "\r\n\r\n"); i > 0 && i+4 < len(payload) {
			resp.Body = string(payload[i+4:])
		}

		return nil, resp, nil
	}

	return nil, nil, fmt.Errorf("not an HTTP message")
}

type GRPCParser struct {
}

func NewGRPCParser() *GRPCParser {
	return &GRPCParser{}
}

func (p *GRPCParser) CanHandle(port uint16, payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	return payload[0] == 0 || payload[0] == 1
}

func (p *GRPCParser) Parse(payload []byte, span *model.Span) (*GRPCMessage, error) {
	if len(payload) < 5 {
		return nil, fmt.Errorf("payload too short for gRPC")
	}

	msg := &GRPCMessage{
		Metadata: make(map[string]string),
	}

	compressed := payload[0]
	length := uint32(payload[1])<<24 | uint32(payload[2])<<16 | uint32(payload[3])<<8 | uint32(payload[4])

	msg.StatusCode = uint32(compressed)

	if len(payload) > 5 {
		body := payload[5:]
		if len(body) >= 5 && body[0] == 0x00 {
			headerLen := uint32(body[1])<<24 | uint32(body[2])<<16 | uint32(body[3])<<8 | uint32(body[4])
			if int(headerLen) <= len(body[5:]) {
				headerData := body[5 : 5+headerLen]
				headerStr := string(headerData)
				for _, line := range strings.Split(headerStr, "\r\n") {
					if line == "" {
						break
					}
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						value := strings.TrimSpace(parts[1])
						msg.Metadata[key] = value
						if strings.ToLower(key) == "x-trace-id" {
							span.TraceID = value
						}
						if strings.ToLower(key) == "x-span-id" {
							span.SpanID = value
						}
						if strings.ToLower(key) == "x-parent-span-id" {
							span.ParentSpanID = value
						}
						if strings.ToLower(key) == ":path" {
							if parts := strings.Split(value, "/"); len(parts) >= 3 {
								msg.ServiceName = parts[1]
								msg.MethodName = parts[2]
							}
						}
					}
				}
			}
		}

		path := ""
		if idx := bytes.Index(payload, []byte("/")); idx > 0 {
			start := idx
			for start > 0 && payload[start-1] != 0 {
				start--
			}
			if end := bytes.Index(payload[start:], []byte{0x00, 0x00, 0x00}); end > 0 {
				path = string(payload[start : start+end])
				if parts := strings.Split(path, "/"); len(parts) >= 3 {
					msg.ServiceName = parts[0]
					msg.MethodName = parts[1]
				}
			}
		}
	}

	_ = length
	return msg, nil
}

type RedisParser struct {
}

func NewRedisParser() *RedisParser {
	return &RedisParser{}
}

func (p *RedisParser) CanHandle(port uint16, payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	first := payload[0]
	return first == '*' || first == '+' || first == '-' || first == ':' || first == '$' ||
		(first >= 'A' && first <= 'Z')
}

func (p *RedisParser) Parse(payload []byte, span *model.Span) (*RedisCommand, error) {
	cmd := &RedisCommand{}

	payloadStr := strings.TrimSpace(string(payload))

	if len(payloadStr) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	first := payloadStr[0]

	if first == '*' {
		lines := strings.Split(payloadStr, "\r\n")
		if len(lines) < 3 {
			return nil, fmt.Errorf("invalid RESP format")
		}

		numArgs, _ := strconv.Atoi(lines[0][1:])
		args := make([]string, 0, numArgs)

		idx := 1
		for i := 0; i < numArgs && idx+1 < len(lines); i++ {
			if lines[idx][0] == '$' {
				idx++
				if idx < len(lines) {
					args = append(args, lines[idx])
					idx++
				}
			}
		}

		if len(args) > 0 {
			cmd.Command = strings.ToUpper(args[0])
			if len(args) > 1 {
				cmd.Key = args[1]
			}
			if len(args) > 2 {
				cmd.Args = args[2:]
			}
		}
	} else if first == '+' || first == '-' || first == ':' || first == '$' {
		cmd.IsResponse = true
		if len(payloadStr) > 1 {
			cmd.Command = string(first)
			parts := strings.SplitN(payloadStr[1:], "\r\n")[0]
			cmd.Key = parts
		}
	} else {
		parts := strings.Fields(payloadStr)
		if len(parts) > 0 {
			cmd.Command = strings.ToUpper(parts[0])
			if len(parts) > 1 {
				cmd.Key = parts[1]
			}
			if len(parts) > 2 {
				cmd.Args = parts[2:]
			}
		}
	}

	span.TraceID = extractTraceIDFromRedis(payload)

	return cmd, nil
}

func extractTraceIDFromRedis(payload []byte) string {
	str := string(payload)
	if idx := strings.Index(str, "TRACE_ID:"); idx > 0 {
		end := idx + len("TRACE_ID:")
		for end < len(str) && str[end] != ' ' && str[end] != '\r' && str[end] != '\n' {
			end++
		}
		return str[idx+len("TRACE_ID:") : end]
	}
	return ""
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (info *ProtocolInfo) ToJSON() (string, error) {
	data, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
