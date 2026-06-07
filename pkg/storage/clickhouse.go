package storage

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

type ClickHouseStats struct {
	TotalSpans        uint64 `json:"total_spans"`
	FlushedBatches    uint64 `json:"flushed_batches"`
	FailedBatches     uint64 `json:"failed_batches"`
	RetriedBatches    uint64 `json:"retried_batches"`
	DroppedSpans     uint64 `json:"dropped_spans"`
	QueueSize          uint64 `json:"queue_size"`
	QueueCapacity    uint64 `json:"queue_capacity"`
}

type ClickHouseStore struct {
	conn          driver.Conn
	database      string
	writeQueue    chan *model.Span
	queueCapacity int
	batchSize     int
	flushInterval time.Duration
	maxRetries    int
	stats         ClickHouseStats
	stopChan      chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
}

func NewClickHouseStore(cfg *config.ClickHouseConfig) (*ClickHouseStore, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	batchSize := 10000
	if cfg.BatchSize > 0 {
		batchSize = cfg.BatchSize
	}

	queueCapacity := 100000
	if cfg.QueueCapacity > 0 {
		queueCapacity = cfg.QueueCapacity
	}

	flushInterval := 5 * time.Second
	if cfg.FlushInterval > 0 {
		flushInterval = time.Duration(cfg.FlushInterval) * time.Second
	}

	maxRetries := 3
	if cfg.MaxRetries > 0 {
		maxRetries = cfg.MaxRetries
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time":        120,
			"async_insert":           1,
			"wait_for_async_insert": 0,
			"async_insert_busy_timeout_ms": 60000,
			"parts_to_delay_insert":    10000,
			"parts_to_throw_insert":  50000,
			"max_partitions_per_insert_block": 1000,
			"insert_quorum":            1,
		},
		DialTimeout:     10 * time.Second,
		MaxOpenConns: cfg.MaxOpenConns,
		MaxIdleConns: cfg.MaxIdleConns,
		ConnMaxLifetime: 1 * time.Hour,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		Debug: false,
	})
	if err != nil {
		return nil, fmt.Errorf("opening clickhouse connection: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	store := &ClickHouseStore{
		conn:          conn,
		database:      cfg.Database,
		writeQueue:    make(chan *model.Span, queueCapacity),
		queueCapacity: queueCapacity,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		maxRetries:    maxRetries,
		stopChan:      make(chan struct{}),
	}

	store.wg.Add(2)
	go store.batchWriter()
	go store.statsReporter()

	log.Printf("ClickHouse store initialized: batch_size=%d, flush_interval=%v, queue_capacity=%d",
		batchSize, flushInterval, queueCapacity)

	return store, nil
}

func (s *ClickHouseStore) InitSchema(ctx context.Context) error {
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
			path String,
			tags String
		) ENGINE = MergeTree()
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, trace_id, span_id)
		TTL timestamp + INTERVAL 30 DAY
		SETTINGS index_granularity = 8192,
		         parts_to_delay_insert = 10000,
		         parts_to_throw_insert = 50000`,
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
	atomic.AddUint64(&s.stats.TotalSpans, 1)

	select {
	case s.writeQueue <- span:
		return nil
	default:
		atomic.AddUint64(&s.stats.DroppedSpans, 1)
		if atomic.LoadUint64(&s.stats.DroppedSpans)%1000 == 0 {
			log.Printf("Warning: write queue full, dropped %d spans so far", atomic.LoadUint64(&s.stats.DroppedSpans))
		}
		return fmt.Errorf("write queue full")
	}
}

func (s *ClickHouseStore) batchWriter() {
	defer s.wg.Done()

	batch := make([]*model.Span, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			s.flushBatch(batch)
			return

		case span := <-s.writeQueue:
			batch = append(batch, span)

			if len(batch) >= s.batchSize {
				s.flushBatch(batch)
				batch = batch[:0]
				ticker.Reset(s.flushInterval)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.flushBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *ClickHouseStore) flushBatch(batch []*model.Span) {
	if len(batch) == 0 {
		return
	}

	ctx := context.Background()

	err := s.flushWithRetry(ctx, batch)
	if err != nil {
		atomic.AddUint64(&s.stats.FailedBatches, 1)
		log.Printf("Error: failed to flush batch after %d retries: %v", s.maxRetries, err)
		return
	}

	atomic.AddUint64(&s.stats.FlushedBatches, 1)
	log.Printf("Flushed %d spans to ClickHouse", len(batch))
}

func (s *ClickHouseStore) flushWithRetry(ctx context.Context, batch []*model.Span) error {
	var lastErr error

	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 {
			atomic.AddUint64(&s.stats.RetriedBatches, 1)
			backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
			time.Sleep(backoff)
		}

		err := s.doFlush(ctx, batch)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Printf("Warning: flush attempt %d/%d failed: %v", attempt+1, s.maxRetries, err)

		if isTooManyParts(err) {
			log.Printf("Too many parts error detected, increasing backoff...")
			time.Sleep(2 * time.Second)
		}
	}

	return fmt.Errorf("flush failed after %d attempts: %w", s.maxRetries, lastErr)
}

func (s *ClickHouseStore) doFlush(ctx context.Context, batch []*model.Span) error {
	timeout := time.Duration(len(batch)/1000) * time.Second
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prepareBatch, err := s.conn.PrepareBatch(ctx, `INSERT INTO spans (
		timestamp, trace_id, span_id, parent_span_id, service_name, operation,
		protocol, event_type, start_time, end_time, duration_ms, error_code,
		payload_size, payload, source_ip, dest_ip, source_port, dest_port,
		pid, comm, path, tags
	) VALUES`)
	if err != nil {
		return fmt.Errorf("preparing batch: %w", err)
	}

	for _, span := range batch {
		tags := ""
		if len(span.Tags) > 0 {
			tags = spanTagsToString(span.Tags)
		}

		err := prepareBatch.Append(
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
			tags,
		)
		if err != nil {
			log.Printf("Warning: failed to append span: %v", err)
			continue
		}
	}

	if err := prepareBatch.Send(); err != nil {
		return fmt.Errorf("sending batch: %w", err)
	}

	return nil
}

func (s *ClickHouseStore) Flush(ctx context.Context) error {
	return nil
}

func (s *ClickHouseStore) statsReporter() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := s.GetStats()
		log.Printf("ClickHouse Stats: total=%d, flushed=%d, failed=%d, retried=%d, dropped=%d, queue=%d/%d",
			stats.TotalSpans, stats.FlushedBatches, stats.FailedBatches,
			stats.RetriedBatches, stats.DroppedSpans,
			stats.QueueSize, stats.QueueCapacity)
	}
}

func (s *ClickHouseStore) GetStats() ClickHouseStats {
	return ClickHouseStats{
		TotalSpans:     atomic.LoadUint64(&s.stats.TotalSpans),
		FlushedBatches:  atomic.LoadUint64(&s.stats.FlushedBatches),
		FailedBatches:   atomic.LoadUint64(&s.stats.FailedBatches),
		RetriedBatches:   atomic.LoadUint64(&s.stats.RetriedBatches),
		DroppedSpans:    atomic.LoadUint64(&s.stats.DroppedSpans),
		QueueSize:       uint64(len(s.writeQueue)),
		QueueCapacity: uint64(s.queueCapacity),
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
		pid, comm, path, tags
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
		var tags string

		err := rows.Scan(
			&span.TraceID, &span.SpanID, &span.ParentSpanID,
			&span.ServiceName, &span.Operation, &span.Protocol, &span.EventType,
			&span.StartTime, &span.EndTime, &span.DurationMs, &span.ErrorCode,
			&span.PayloadSize, &span.Payload, &sourceIP, &destIP,
			&span.SourcePort, &span.DestPort, &span.PID, &span.Comm, &span.Path, &tags,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning span: %w", err)
		}

		span.TraceID = strings.TrimSpace(span.TraceID)
		span.SpanID = strings.TrimSpace(span.SpanID)
		span.ParentSpanID = strings.TrimSpace(span.ParentSpanID)
		span.SourceIP = sourceIP.String()
		span.DestIP = destIP.String()
		span.Tags = parseSpanTags(tags)

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
		var operation, protocol string
		var callCount, errorCount uint64
		var avgDuration, p50, p95, p99 float64

		err := rows.Scan(
			&operation, &protocol, &callCount, &errorCount,
			&avgDuration, &p50, &p95, &p99,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning stats: %w", err)
		}

		op := map[string]interface{}{
			"operation":       operation,
			"protocol":        protocol,
			"call_count":      callCount,
			"error_count":     errorCount,
			"avg_duration_ms": avgDuration,
			"p50_duration_ms": p50,
			"p95_duration_ms": p95,
			"p99_duration_ms": p99,
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
		var sourceService, destService, protocol string
		var callCount, errorCount uint64
		var avgDuration float64

		err := rows.Scan(
			&sourceService, &destService, &protocol,
			&callCount, &errorCount, &avgDuration,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning edge: %w", err)
		}

		edge := map[string]interface{}{
			"source_service":   sourceService,
			"dest_service":     destService,
			"protocol":         protocol,
			"call_count":       callCount,
			"error_count":      errorCount,
			"avg_duration_ms":  avgDuration,
		}
		edges = append(edges, edge)
	}

	return edges, rows.Err()
}

func (s *ClickHouseStore) Close() error {
	close(s.stopChan)
	s.wg.Wait()

	close(s.writeQueue)

	return s.conn.Close()
}

func isTooManyParts(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Too many parts")
}

func spanTagsToString(tags map[string]interface{}) string {
	if len(tags) == 0 {
		return ""
	}
	var parts []string
	for k, v := range tags {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, ",")
}

func parseSpanTags(s string) map[string]interface{} {
	tags := make(map[string]interface{})
	if s == "" {
		return tags
	}
	parts := strings.Split(s, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			tags[kv[0]] = kv[1]
		}
	}
	return tags
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
