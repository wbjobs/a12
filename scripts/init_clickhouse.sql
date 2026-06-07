CREATE DATABASE IF NOT EXISTS ebpf_apm;

USE ebpf_apm;

CREATE TABLE IF NOT EXISTS spans (
    timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
    trace_id FixedString(32) CODEC(ZSTD(1)),
    span_id FixedString(16) CODEC(ZSTD(1)),
    parent_span_id FixedString(16) CODEC(ZSTD(1)),
    service_name LowCardinality(String) CODEC(ZSTD(1)),
    operation String CODEC(ZSTD(1)),
    protocol LowCardinality(String) CODEC(ZSTD(1)),
    event_type LowCardinality(String) CODEC(ZSTD(1)),
    start_time DateTime64(9) CODEC(Delta, ZSTD(1)),
    end_time DateTime64(9) CODEC(Delta, ZSTD(1)),
    duration_ms Float64 CODEC(ZSTD(1)),
    error_code Int32 CODEC(ZSTD(1)),
    payload_size UInt32 CODEC(ZSTD(1)),
    payload String CODEC(ZSTD(3)),
    source_ip IPv4 CODEC(ZSTD(1)),
    dest_ip IPv4 CODEC(ZSTD(1)),
    source_port UInt16 CODEC(ZSTD(1)),
    dest_port UInt16 CODEC(ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    comm String CODEC(ZSTD(1)),
    path String CODEC(ZSTD(1)),
    INDEX idx_trace_id trace_id TYPE bloom_filter(0.01) GRANULARITY 64,
    INDEX idx_service service_name TYPE set(1000) GRANULARITY 64,
    INDEX idx_duration duration_ms TYPE minmax GRANULARITY 64,
    INDEX idx_error error_code TYPE set(100) GRANULARITY 64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, trace_id, span_id)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS service_map (
    timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
    source_service LowCardinality(String) CODEC(ZSTD(1)),
    dest_service LowCardinality(String) CODEC(ZSTD(1)),
    protocol LowCardinality(String) CODEC(ZSTD(1)),
    call_count UInt64 CODEC(ZSTD(1)),
    error_count UInt64 CODEC(ZSTD(1)),
    avg_duration_ms Float64 CODEC(ZSTD(1)),
    p95_duration_ms Float64 CODEC(ZSTD(1)),
    p99_duration_ms Float64 CODEC(ZSTD(1))
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_service, dest_service, protocol)
TTL timestamp + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS service_stats (
    timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
    service_name LowCardinality(String) CODEC(ZSTD(1)),
    operation String CODEC(ZSTD(1)),
    protocol LowCardinality(String) CODEC(ZSTD(1)),
    call_count UInt64 CODEC(ZSTD(1)),
    error_count UInt64 CODEC(ZSTD(1)),
    avg_duration_ms Float64 CODEC(ZSTD(1)),
    min_duration_ms Float64 CODEC(ZSTD(1)),
    max_duration_ms Float64 CODEC(ZSTD(1)),
    p50_duration_ms Float64 CODEC(ZSTD(1)),
    p90_duration_ms Float64 CODEC(ZSTD(1)),
    p95_duration_ms Float64 CODEC(ZSTD(1)),
    p99_duration_ms Float64 CODEC(ZSTD(1)),
    total_payload_size UInt64 CODEC(ZSTD(1))
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, service_name, operation, protocol)
TTL timestamp + INTERVAL 7 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS service_stats_mv TO service_stats
AS SELECT
    toStartOfMinute(start_time) AS timestamp,
    service_name,
    operation,
    protocol,
    count() AS call_count,
    countIf(error_code != 0 AND error_code >= 400) AS error_count,
    avg(duration_ms) AS avg_duration_ms,
    min(duration_ms) AS min_duration_ms,
    max(duration_ms) AS max_duration_ms,
    quantile(0.5)(duration_ms) AS p50_duration_ms,
    quantile(0.90)(duration_ms) AS p90_duration_ms,
    quantile(0.95)(duration_ms) AS p95_duration_ms,
    quantile(0.99)(duration_ms) AS p99_duration_ms,
    sum(payload_size) AS total_payload_size
FROM spans
GROUP BY
    timestamp,
    service_name,
    operation,
    protocol;

CREATE MATERIALIZED VIEW IF NOT EXISTS service_map_mv TO service_map
AS SELECT
    toStartOfMinute(start_time) AS timestamp,
    service_name AS source_service,
    dest_service,
    protocol,
    count() AS call_count,
    countIf(error_code != 0 AND error_code >= 400) AS error_count,
    avg(duration_ms) AS avg_duration_ms,
    quantile(0.95)(duration_ms) AS p95_duration_ms,
    quantile(0.99)(duration_ms) AS p99_duration_ms
FROM (
    SELECT
        s1.trace_id,
        s1.service_name,
        s2.service_name AS dest_service,
        s1.protocol,
        s1.duration_ms,
        s1.error_code,
        s1.start_time
    FROM spans s1
    INNER JOIN spans s2 ON s1.trace_id = s2.trace_id AND s1.parent_span_id = s2.span_id
    WHERE s1.parent_span_id != ''
)
GROUP BY
    timestamp,
    source_service,
    dest_service,
    protocol;
