package sampling

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

type Sampler interface {
	ShouldSample(span *model.Span) bool
	SamplingRate(span *model.Span) float64
}

type DynamicSampler struct {
	highLatencyThresholdMs int64
	highLatencySampleRate  float64
	lowLatencySampleRate   float64
	totalCount             atomic.Uint64
	sampledCount           atomic.Uint64
	highLatencyCount       atomic.Uint64
	lowLatencyCount        atomic.Uint64
	mu                     sync.RWMutex
}

func NewDynamicSampler(cfg *config.SamplingConfig) *DynamicSampler {
	return &DynamicSampler{
		highLatencyThresholdMs: int64(cfg.HighLatencyThresholdMs),
		highLatencySampleRate:  cfg.HighLatencySampleRate,
		lowLatencySampleRate:   cfg.LowLatencySampleRate,
	}
}

func (s *DynamicSampler) ShouldSample(span *model.Span) bool {
	s.totalCount.Add(1)

	rate := s.SamplingRate(span)
	if rate >= 1.0 {
		s.sampledCount.Add(1)
		s.highLatencyCount.Add(1)
		return true
	}

	if rate <= 0 {
		return false
	}

	if rand.Float64() < rate {
		s.sampledCount.Add(1)
		s.lowLatencyCount.Add(1)
		return true
	}

	return false
}

func (s *DynamicSampler) SamplingRate(span *model.Span) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if span.DurationMs >= float64(s.highLatencyThresholdMs) {
		return s.highLatencySampleRate
	}

	if span.ErrorCode != 0 && span.ErrorCode >= 400 {
		return s.highLatencySampleRate
	}

	return s.lowLatencySampleRate
}

func (s *DynamicSampler) UpdateConfig(cfg *config.SamplingConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.highLatencyThresholdMs = int64(cfg.HighLatencyThresholdMs)
	s.highLatencySampleRate = cfg.HighLatencySampleRate
	s.lowLatencySampleRate = cfg.LowLatencySampleRate
}

type Stats struct {
	TotalCount         uint64  `json:"totalCount"`
	SampledCount       uint64  `json:"sampledCount"`
	HighLatencyCount   uint64  `json:"highLatencyCount"`
	LowLatencyCount    uint64  `json:"lowLatencyCount"`
	OverallSampleRate  float64 `json:"overallSampleRate"`
	HighLatencyRate    float64 `json:"highLatencyRate"`
	LowLatencyRate     float64 `json:"lowLatencyRate"`
	ThresholdMs        int64   `json:"thresholdMs"`
}

func (s *DynamicSampler) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := s.totalCount.Load()
	sampled := s.sampledCount.Load()

	var overallRate float64
	if total > 0 {
		overallRate = float64(sampled) / float64(total)
	}

	return Stats{
		TotalCount:        total,
		SampledCount:      sampled,
		HighLatencyCount:  s.highLatencyCount.Load(),
		LowLatencyCount:   s.lowLatencyCount.Load(),
		OverallSampleRate: overallRate,
		HighLatencyRate:   s.highLatencySampleRate,
		LowLatencyRate:    s.lowLatencySampleRate,
		ThresholdMs:       s.highLatencyThresholdMs,
	}
}

func (s *DynamicSampler) ResetStats() {
	s.totalCount.Store(0)
	s.sampledCount.Store(0)
	s.highLatencyCount.Store(0)
	s.lowLatencyCount.Store(0)
}

type AdaptiveSampler struct {
	*DynamicSampler
	targetEventsPerSecond int
	eventsWindow          []time.Time
	windowMutex           sync.Mutex
	windowDuration        time.Duration
}

func NewAdaptiveSampler(cfg *config.SamplingConfig, targetEPS int) *AdaptiveSampler {
	return &AdaptiveSampler{
		DynamicSampler:        NewDynamicSampler(cfg),
		targetEventsPerSecond: targetEPS,
		windowDuration:        10 * time.Second,
	}
}

func (s *AdaptiveSampler) ShouldSample(span *model.Span) bool {
	s.addEvent(time.Now())

	if span.DurationMs >= float64(s.highLatencyThresholdMs) {
		s.sampledCount.Add(1)
		s.highLatencyCount.Add(1)
		return true
	}

	if span.ErrorCode != 0 && span.ErrorCode >= 400 {
		s.sampledCount.Add(1)
		return true
	}

	currentEPS := s.currentEPS()
	rate := s.calculateAdaptiveRate(currentEPS)

	s.totalCount.Add(1)

	if rand.Float64() < rate {
		s.sampledCount.Add(1)
		s.lowLatencyCount.Add(1)
		return true
	}

	return false
}

func (s *AdaptiveSampler) calculateAdaptiveRate(currentEPS float64) float64 {
	if currentEPS <= float64(s.targetEventsPerSecond) {
		return 1.0
	}

	ratio := float64(s.targetEventsPerSecond) / currentEPS
	baseRate := s.DynamicSampler.SamplingRate(nil)

	return baseRate * ratio
}

func (s *AdaptiveSampler) addEvent(t time.Time) {
	s.windowMutex.Lock()
	defer s.windowMutex.Unlock()

	s.eventsWindow = append(s.eventsWindow, t)
	s.pruneOldEvents(t)
}

func (s *AdaptiveSampler) currentEPS() float64 {
	s.windowMutex.Lock()
	defer s.windowMutex.Unlock()

	now := time.Now()
	s.pruneOldEvents(now)

	return float64(len(s.eventsWindow)) / s.windowDuration.Seconds()
}

func (s *AdaptiveSampler) pruneOldEvents(now time.Time) {
	cutoff := now.Add(-s.windowDuration)
	idx := 0
	for ; idx < len(s.eventsWindow); idx++ {
		if s.eventsWindow[idx].After(cutoff) {
			break
		}
	}
	s.eventsWindow = s.eventsWindow[idx:]
}

type TraceLevelSampler struct {
	sampledTraces sync.Map
	innerSampler  Sampler
}

func NewTraceLevelSampler(inner Sampler) *TraceLevelSampler {
	return &TraceLevelSampler{
		innerSampler: inner,
	}
}

func (s *TraceLevelSampler) ShouldSample(span *model.Span) bool {
	if span.TraceID == "" {
		return s.innerSampler.ShouldSample(span)
	}

	if entry, ok := s.sampledTraces.Load(span.TraceID); ok {
		if sampled, ok := entry.(struct {
			Sampled   bool
			Timestamp time.Time
		}); ok {
			return sampled.Sampled
		}
	}

	shouldSample := s.innerSampler.ShouldSample(span)
	s.sampledTraces.Store(span.TraceID, struct {
		Sampled   bool
		Timestamp time.Time
	}{
		Sampled:   shouldSample,
		Timestamp: time.Now(),
	})

	return shouldSample
}

func (s *TraceLevelSampler) SamplingRate(span *model.Span) float64 {
	return s.innerSampler.SamplingRate(span)
}

func (s *TraceLevelSampler) cleanupOldTraces() {
	for {
		time.Sleep(5 * time.Minute)

		cutoff := time.Now().Add(-10 * time.Minute)

		var toDelete []string
		s.sampledTraces.Range(func(key, value interface{}) bool {
			if entry, ok := value.(struct {
				Sampled   bool
				Timestamp time.Time
			}); ok && entry.Timestamp.Before(cutoff) {
				toDelete = append(toDelete, key.(string))
			}
			return true
		})

		for _, k := range toDelete {
			s.sampledTraces.Delete(k)
		}
	}
}

func (s *TraceLevelSampler) MarkTraceSampled(traceID string) {
	s.sampledTraces.Store(traceID, struct {
		Sampled   bool
		Timestamp time.Time
	}{
		Sampled:   true,
		Timestamp: time.Now(),
	})
}

func (s *TraceLevelSampler) IsTraceSampled(traceID string) bool {
	if entry, ok := s.sampledTraces.Load(traceID); ok {
		if sampled, ok := entry.(struct {
			Sampled   bool
			Timestamp time.Time
		}); ok {
			return sampled.Sampled
		}
	}
	return false
}

type CompositeSampler struct {
	samplers []Sampler
}

func NewCompositeSampler(samplers ...Sampler) *CompositeSampler {
	return &CompositeSampler{
		samplers: samplers,
	}
}

func (s *CompositeSampler) ShouldSample(span *model.Span) bool {
	for _, sampler := range s.samplers {
		if !sampler.ShouldSample(span) {
			return false
		}
	}
	return true
}

func (s *CompositeSampler) SamplingRate(span *model.Span) float64 {
	minRate := 1.0
	for _, sampler := range s.samplers {
		rate := sampler.SamplingRate(span)
		if rate < minRate {
			minRate = rate
		}
	}
	return minRate
}
