package sampling

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

func TestDynamicSampler(t *testing.T) {
	cfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 500,
		HighLatencySampleRate:  1.0,
		LowLatencySampleRate:   0.01,
	}

	sampler := NewDynamicSampler(cfg)

	highLatencySpan := &model.Span{
		TraceID:    "test-trace-1",
		DurationMs: 600,
		ErrorCode:  0,
	}

	for i := 0; i < 100; i++ {
		assert.True(t, sampler.ShouldSample(highLatencySpan),
			"High latency spans should always be sampled")
	}

	lowLatencySpan := &model.Span{
		TraceID:    "test-trace-2",
		DurationMs: 100,
		ErrorCode:  0,
	}

	sampledCount := 0
	for i := 0; i < 10000; i++ {
		if sampler.ShouldSample(lowLatencySpan) {
			sampledCount++
		}
	}

	assert.InDelta(t, 100, sampledCount, 50,
		"Low latency sampling rate should be approximately 1%")

	errorSpan := &model.Span{
		TraceID:    "test-trace-3",
		DurationMs: 100,
		ErrorCode:  500,
	}
	assert.True(t, sampler.ShouldSample(errorSpan),
		"Error spans should always be sampled")

	stats := sampler.Stats()
	assert.Greater(t, stats.TotalCount, uint64(0))
	assert.Equal(t, float64(1.0), stats.HighLatencyRate)
	assert.Equal(t, float64(0.01), stats.LowLatencyRate)
	assert.Equal(t, int64(500), stats.ThresholdMs)
}

func TestTraceLevelSampler(t *testing.T) {
	cfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 500,
		HighLatencySampleRate:  0.0,
		LowLatencySampleRate:   0.0,
	}

	innerSampler := NewDynamicSampler(cfg)
	traceSampler := NewTraceLevelSampler(innerSampler)

	span1 := &model.Span{
		TraceID:    "trace-same-1",
		SpanID:     "span-1",
		DurationMs: 100,
	}

	span2 := &model.Span{
		TraceID:      "trace-same-1",
		SpanID:       "span-2",
		ParentSpanID: "span-1",
		DurationMs:   50,
	}

	sampled1 := traceSampler.ShouldSample(span1)
	sampled2 := traceSampler.ShouldSample(span2)

	assert.Equal(t, sampled1, sampled2,
		"Spans in the same trace should have consistent sampling decision")

	traceSampler.MarkTraceSampled("force-sampled-trace")
	forceSpan := &model.Span{
		TraceID:    "force-sampled-trace",
		DurationMs: 100,
	}
	assert.True(t, traceSampler.ShouldSample(forceSpan),
		"Marked trace should be sampled")

	assert.True(t, traceSampler.IsTraceSampled("force-sampled-trace"))
	assert.False(t, traceSampler.IsTraceSampled("not-sampled-trace"))
}

func TestCompositeSampler(t *testing.T) {
	cfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 500,
		HighLatencySampleRate:  1.0,
		LowLatencySampleRate:   1.0,
	}

	sampler1 := NewDynamicSampler(cfg)
	sampler2 := NewDynamicSampler(cfg)

	composite := NewCompositeSampler(sampler1, sampler2)

	span := &model.Span{
		TraceID:    "test",
		DurationMs: 600,
	}

	assert.True(t, composite.ShouldSample(span))
	assert.Equal(t, 1.0, composite.SamplingRate(span))
}

func TestSamplingRate(t *testing.T) {
	cfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 500,
		HighLatencySampleRate:  1.0,
		LowLatencySampleRate:   0.5,
	}

	sampler := NewDynamicSampler(cfg)

	highSpan := &model.Span{DurationMs: 1000}
	assert.Equal(t, 1.0, sampler.SamplingRate(highSpan))

	lowSpan := &model.Span{DurationMs: 100}
	assert.Equal(t, 0.5, sampler.SamplingRate(lowSpan))

	errorSpan := &model.Span{DurationMs: 100, ErrorCode: 404}
	assert.Equal(t, 1.0, sampler.SamplingRate(errorSpan))
}

func TestUpdateConfig(t *testing.T) {
	cfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 500,
		HighLatencySampleRate:  1.0,
		LowLatencySampleRate:   0.01,
	}

	sampler := NewDynamicSampler(cfg)

	newCfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 1000,
		HighLatencySampleRate:  0.5,
		LowLatencySampleRate:   0.001,
	}

	sampler.UpdateConfig(newCfg)

	span := &model.Span{DurationMs: 700, ErrorCode: 0}
	rate := sampler.SamplingRate(span)
	assert.Equal(t, 0.001, rate,
		"700ms should now be considered low latency with 0.001 rate")

	highSpan := &model.Span{DurationMs: 1500}
	highRate := sampler.SamplingRate(highSpan)
	assert.Equal(t, 0.5, highRate,
		"1500ms should be high latency with 0.5 rate")
}

func BenchmarkDynamicSampler(b *testing.B) {
	cfg := &config.SamplingConfig{
		HighLatencyThresholdMs: 500,
		HighLatencySampleRate:  1.0,
		LowLatencySampleRate:   0.01,
	}

	sampler := NewDynamicSampler(cfg)
	span := &model.Span{
		TraceID:    "bench-trace",
		DurationMs: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sampler.ShouldSample(span)
	}
}
