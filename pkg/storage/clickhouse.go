package storage

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

type ClickHouseStore struct {
	conn     driver.Conn
	database string
	batch    []*model.Span
	batchSize int
	mu       chan struct{}
}

func NewClickHouseStore(cfg *config.ClickHouseConfig) (*ClickHouseStore, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout:     5 * time.Second,
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: 1 * time.Hour,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		Debug: false,
	})
	if err != nil {
		return nil, fmt.Errorf("opening clickhouse connection: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	store := &ClickHouseStore{
		conn:      conn,
		database:  cfg.Database,
		batch:     make([]*model.Span, 0, 1000),
		batchSize: 1000,
		mu:        make(chan struct{}, 1),
	}

	go store.flushLoop()
	return store, nil
}

func (s *ClickHouseStore) InitSchema(ctx context.Context) error {
	sqlFiles := []string{
		"scripts/init_clickhouse.sql",
	}

	for _, file := range sqlFiles {
		log.Printf("Executing schema file: %s", file)
	}

	queries := []string{
		`CREATE DATABASE IF NOT EXISTS ` + s.database,
		`USE ` + s.database,
		`CREATE TABLE IF NOT EXISTS spans (
			timestamp DateTime64(9),
			trace_id FixedString(32),
			span_id FixedString(16),
			parent_span_id FixedString(16),
			service_name LowCardinality(String),
			operation String,
			protocol LowCardinality(String),
			event_type LowCardinality(String),
			start_time DateTime64(9),
			end_time DateTime64(9),
			duration_ms Float64,
			error_code Int32,
			payload_size UInt32,
			payload String,
			source_ip IPv4,
			dest_ip IPv4,
			source_port UInt16,
			dest_port UInt16,
			pid UInt32,
			comm String,
			path String
		) ENGINE = MergeTree()
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, trace_id, span_id)
		TTL timestamp + INTERVAL 30 DAY`,
	}

	for _, query := range queries {
		if err := s.conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("executing query: %w", err)
		}
	}

	log.Println("ClickHouse schema initialized successfully")
	return nil
}

func (s *ClickHouseStore) SaveSpan(ctx context.Context, span *model.Span) error {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()

	s.batch = append(s.batch, span)

	if len(s.batch) >= s.batchSize {
		return s.flushBatchLocked(ctx)
	}

	return nil
}

func (s *ClickHouseStore) Flush(ctx context.Context) error {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()

	return s.flushBatchLocked(ctx)
}

func (s *ClickHouseStore) flushBatchLocked(ctx context.Context) error {
	if len(s.batch) == 0 {
		return nil
	}

	batch, err := s.conn.PrepareBatch(ctx, `INSERT INTO spans (
		timestamp, trace_id, span_id, parent_span_id, service_name, operation,
		protocol, event_type, start_time, end_time, duration_ms, error_code,
		payload_size, payload, source_ip, dest_ip, source_port, dest_port,
		pid, comm, path
	) VALUES`)
	if err != nil {
		return fmt.Errorf("preparing batch: %w", err)
	}

	for _, span := range s.batch {
		err := batch.Append(
			span.StartTime,
			padString(span.TraceID, 32),
			padString(span.SpanID, 16),
			padString(span.ParentSpanID, 16),
			span.ServiceName,
			span.Operation,
			span.Protocol,
			span.EventType,
			span.StartTime,
			span.EndTime,
			span.DurationMs,
			span.ErrorCode,
			span.PayloadSize,
			truncate(span.Payload, 1024),
			net.ParseIP(span.SourceIP),
			net.ParseIP(span.DestIP),
			span.SourcePort,
			span.DestPort,
			span.PID,
			span.Comm,
			span.Path,
		)
		if err != nil {
			log.Printf("Warning: failed to append span: %v", err)
			continue
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("sending batch: %w", err)
	}

	log.Printf("Flushed %d spans to ClickHouse", len(s.batch))
	s.batch = s.batch[:0]
	return nil
}

func (s *ClickHouseStore) flushLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.Flush(ctx); err != nil {
			log.Printf("Error flushing spans: %v", err)
		}
		cancel()
	}
}

func (s *ClickHouseStore) GetTraceByID(ctx context.Context, traceID string) (*model.Trace, error) {
	if traceID == "" {
		return nil, fmt.Errorf("trace_id is required")
	}

	query := `SELECT 
		trace_id, span_id, parent_span_id, service_name, operation,
		protocol, event_type, start_time, end_time, duration_ms, error_code,
		payload_size, payload, source_ip, dest_ip, source_port, dest_port,
		pid, comm, path
	FROM spans 
	WHERE trace_id = ? 
	ORDER BY start_time ASC`

	rows, err := s.conn.Query(ctx, query, padString(traceID, 32))
	if err != nil {
		return nil, fmt.Errorf("querying trace: %w", err)
	}
	defer rows.Close()

	spans := make([]*model.Span, 0)
	for rows.Next() {
		span := &model.Span{}
		var sourceIP, destIP net.IP
		
		err := rows.Scan(
			&span.TraceID, &span.SpanID, &span.ParentSpanID,
			&span.ServiceName, &span.Operation, &span.Protocol, &span.EventType,
			&span.StartTime, &span.EndTime, &span.DurationMs, &span.ErrorCode,
			&span.PayloadSize, &span.Payload, &sourceIP, &destIP,
			&span.SourcePort, &span.DestPort, &span.PID, &span.Comm, &span.Path,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning span: %w", err)
		}

		span.TraceID = strings.TrimSpace(span.TraceID)
		span.SpanID = strings.TrimSpace(span.SpanID)
		span.ParentSpanID = strings.TrimSpace(span.ParentSpanID)
		span.SourceIP = sourceIP.String()
		span.DestIP = destIP.String()

		spans = append(spans, span)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	if len(spans) == 0 {
		return nil, fmt.Errorf("trace not found: %s", traceID)
	}

	return model.BuildTraceTree(spans), nil
}

func (s *ClickHouseStore) QueryTraces(ctx context.Context, query *model.TraceQuery) ([]*model.Trace, error) {
	var builder strings.Builder
	builder.WriteString(`SELECT DISTINCT trace_id FROM spans WHERE 1=1`)
	args := make([]interface{}, 0)

	if query.ServiceName != "" {
		builder.WriteString(` AND service_name = ?`)
		args = append(args, query.ServiceName)
	}

	if query.StartTime != nil {
		builder.WriteString(` AND start_time >= ?`)
		args = append(args, *query.StartTime)
	}

	if query.EndTime != nil {
		builder.WriteString(` AND start_time <= ?`)
		args = append(args, *query.EndTime)
	}

	if query.MinLatencyMs != nil {
		builder.WriteString(` AND duration_ms >= ?`)
		args = append(args, *query.MinLatencyMs)
	}

	if query.MaxLatencyMs != nil {
		builder.WriteString(` AND duration_ms <= ?`)
		args = append(args, *query.MaxLatencyMs)
	}

	if query.Protocol != "" {
		builder.WriteString(` AND protocol = ?`)
		args = append(args, query.Protocol)
	}

	if query.TraceID != "" {
		builder.WriteString(` AND trace_id = ?`)
		args = append(args, padString(query.TraceID, 32))
	}

	builder.WriteString(` ORDER BY start_time DESC`)

	if query.Limit > 0 {
		builder.WriteString(` LIMIT ?`)
		args = append(args, query.Limit)
	}

	if query.Offset > 0 {
		builder.WriteString(` OFFSET ?`)
		args = append(args, query.Offset)
	}

	rows, err := s.conn.Query(ctx, builder.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("querying traces: %w", err)
	}
	defer rows.Close()

	traceIDs := make([]string, 0)
	for rows.Next() {
		var traceID string
		if err := rows.Scan(&traceID); err != nil {
			return nil, fmt.Errorf("scanning trace_id: %w", err)
		}
		traceIDs = append(traceIDs, strings.TrimSpace(traceID))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	traces := make([]*model.Trace, 0, len(traceIDs))
	for _, traceID := range traceIDs {
		trace, err := s.GetTraceByID(ctx, traceID)
		if err != nil {
			log.Printf("Warning: failed to get trace %s: %v", traceID, err)
			continue
		}
		traces = append(traces, trace)
	}

	return traces, nil
}

func (s *ClickHouseStore) GetServices(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT service_name FROM spans ORDER BY service_name`
	rows, err := s.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("querying services: %w", err)
	}
	defer rows.Close()

	services := make([]string, 0)
	for rows.Next() {
		var service string
		if err := rows.Scan(&service); err != nil {
			return nil, fmt.Errorf("scanning service: %w", err)
		}
		services = append(services, service)
	}

	return services, rows.Err()
}

func (s *ClickHouseStore) GetServiceStats(ctx context.Context, serviceName string, startTime, endTime time.Time) (map[string]interface{}, error) {
	query := `SELECT
		operation,
		protocol,
		count() as call_count,
		countIf(error_code != 0 AND error_code >= 400) as error_count,
		avg(duration_ms) as avg_duration,
		quantile(0.5)(duration_ms) as p50,
		quantile(0.95)(duration_ms) as p95,
		quantile(0.99)(duration_ms) as p99
	FROM spans
	WHERE service_name = ? AND start_time >= ? AND start_time <= ?
	GROUP BY operation, protocol
	ORDER BY call_count DESC`

	rows, err := s.conn.Query(ctx, query, serviceName, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("querying service stats: %w", err)
	}
	defer rows.Close()

	result := make(map[string]interface{})
	operations := make([]map[string]interface{}, 0)

	for rows.Next() {
		var op map[string]interface{} = make(map[string]interface{})
		err := rows.Scan(
			&op["operation"], &op["protocol"], &op["call_count"], &op["error_count"],
			&op["avg_duration_ms"], &op["p50_duration_ms"], &op["p95_duration_ms"], &op["p99_duration_ms"],
		)
		if err != nil {
			return nil, fmt.Errorf("scanning stats: %w", err)
		}
		operations = append(operations, op)
	}

	result["service"] = serviceName
	result["operations"] = operations
	result["start_time"] = startTime
	result["end_time"] = endTime

	return result, rows.Err()
}

func (s *ClickHouseStore) GetServiceMap(ctx context.Context, startTime, endTime time.Time) ([]map[string]interface{}, error) {
	query := `SELECT
		s1.service_name as source_service,
		s2.service_name as dest_service,
		s1.protocol,
		count() as call_count,
		countIf(s1.error_code != 0 AND s1.error_code >= 400) as error_count,
		avg(s1.duration_ms) as avg_duration
	FROM spans s1
	INNER JOIN spans s2 ON s1.trace_id = s2.trace_id AND s1.parent_span_id = s2.span_id
	WHERE s1.start_time >= ? AND s1.start_time <= ? AND s1.parent_span_id != ''
	GROUP BY source_service, dest_service, s1.protocol`

	rows, err := s.conn.Query(ctx, query, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("querying service map: %w", err)
	}
	defer rows.Close()

	edges := make([]map[string]interface{}, 0)
	for rows.Next() {
		edge := make(map[string]interface{})
		err := rows.Scan(
			&edge["source_service"], &edge["dest_service"], &edge["protocol"],
			&edge["call_count"], &edge["error_count"], &edge["avg_duration_ms"],
		)
		if err != nil {
			return nil, fmt.Errorf("scanning edge: %w", err)
		}
		edges = append(edges, edge)
	}

	return edges, rows.Err()
}

func (s *ClickHouseStore) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Flush(ctx); err != nil {
		log.Printf("Warning: error flushing on close: %v", err)
	}

	return s.conn.Close()
}

func padString(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + strings.Repeat("\x00", length-len(s))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
