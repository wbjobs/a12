package anomaly

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

type LatencyStats struct {
	Count        uint64  `json:"count"`
	Sum          float64 `json:"sum"`
	SumSq        float64 `json:"sum_sq"`
	EWMA         float64 `json:"ewma"`
	EWMAVar      float64 `json:"ewma_var"`
	Mean         float64 `json:"mean"`
	StdDev       float64 `json:"std_dev"`
	P50          float64 `json:"p50"`
	P95          float64 `json:"p95"`
	P99          float64 `json:"p99"`
	Alpha        float64 `json:"alpha"`
	LastUpdate   time.Time `json:"last_update"`
}

type AnomalyAlert struct {
	TraceID      string                 `json:"trace_id"`
	SpanID       string                 `json:"span_id"`
	ServiceName  string                 `json:"service_name"`
	Operation    string                 `json:"operation"`
	Timestamp    time.Time              `json:"timestamp"`
	Severity     string                 `json:"severity"`
	AnomalyType  string                 `json:"anomaly_type"`
	Description  string                 `json:"description"`
	CurrentValue float64                `json:"current_value"`
	Threshold    float64                `json:"threshold"`
	Deviation    float64                `json:"deviation_percent"`
	Tags         map[string]interface{} `json:"tags,omitempty"`
}

type AlertManagerConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	URL       string `mapstructure:"url"`
	TimeoutMs int    `mapstructure:"timeout_ms"`
}

type DetectorConfig struct {
	Alpha             float64              `mapstructure:"alpha"`
	DeviationThreshold float64            `mapstructure:"deviation_threshold"`
	MinSamples        int                  `mapstructure:"min_samples"`
	CooldownSeconds   int                  `mapstructure:"cooldown_seconds"`
	AlertManager      AlertManagerConfig   `mapstructure:"alertmanager"`
}

type OperationKey struct {
	ServiceName string
	Operation   string
	Protocol    string
}

type AnomalyDetector struct {
	stats       map[OperationKey]*LatencyStats
	statsMutex  sync.RWMutex
	config      *DetectorConfig
	alertChan   chan *AnomalyAlert
	cooldown    map[string]time.Time
	cooldownMu  sync.Mutex
	stopChan    chan struct{}
}

func NewAnomalyDetector(config *DetectorConfig) *AnomalyDetector {
	if config == nil {
		config = &DetectorConfig{
			Alpha:              0.2,
			DeviationThreshold: 3.0,
			MinSamples:         100,
			CooldownSeconds:    60,
		}
	}

	ad := &AnomalyDetector{
		stats:     make(map[OperationKey]*LatencyStats),
		config:    config,
		alertChan: make(chan *AnomalyAlert, 10000),
		cooldown:  make(map[string]time.Time),
		stopChan:  make(chan struct{}),
	}

	if config.AlertManager.Enabled {
		go ad.alertSender()
	}

	go ad.statsCleanupLoop()

	return ad
}

func (ad *AnomalyDetector) RecordSpan(span *model.Span) *AnomalyAlert {
	if span == nil || span.DurationMs <= 0 {
		return nil
	}

	key := OperationKey{
		ServiceName: span.ServiceName,
		Operation:   span.Operation,
		Protocol:    span.Protocol,
	}

	ad.statsMutex.Lock()
	defer ad.statsMutex.Unlock()

	stats, exists := ad.stats[key]
	if !exists {
		stats = &LatencyStats{
			Alpha:      ad.config.Alpha,
			LastUpdate: time.Now(),
		}
		ad.stats[key] = stats
	}

	stats.Count++
	stats.Sum += span.DurationMs
	stats.SumSq += span.DurationMs * span.DurationMs
	stats.LastUpdate = time.Now()

	if stats.EWMA == 0 {
		stats.EWMA = span.DurationMs
		stats.EWMAVar = 0
	} else {
		diff := span.DurationMs - stats.EWMA
		stats.EWMA += ad.config.Alpha * diff
		stats.EWMAVar = (1 - ad.config.Alpha) * (stats.EWMAVar + ad.config.Alpha*diff*diff)
	}

	stats.Mean = stats.Sum / float64(stats.Count)
	if stats.Count > 1 {
		variance := (stats.SumSq - stats.Sum*stats.Sum/float64(stats.Count)) / float64(stats.Count-1)
		stats.StdDev = math.Sqrt(math.Max(0, variance))
	}

	if stats.Count < uint64(ad.config.MinSamples) {
		return nil
	}

	threshold := stats.EWMA + ad.config.DeviationThreshold*math.Sqrt(stats.EWMAVar)

	if span.DurationMs > threshold {
		deviation := (span.DurationMs - stats.EWMA) / stats.EWMA * 100

		severity := "warning"
		if deviation > 500 {
			severity = "critical"
		} else if deviation > 200 {
			severity = "error"
		}

		alert := &AnomalyAlert{
			TraceID:      span.TraceID,
			SpanID:       span.SpanID,
			ServiceName:  span.ServiceName,
			Operation:    span.Operation,
			Timestamp:    time.Now(),
			Severity:     severity,
			AnomalyType:  "latency_spike",
			Description:  fmt.Sprintf("Latency anomaly detected: %.2fms exceeds threshold %.2fms", span.DurationMs, threshold),
			CurrentValue: span.DurationMs,
			Threshold:    threshold,
			Deviation:    deviation,
			Tags:         span.Tags,
		}

		if ad.shouldSendAlert(key, severity) {
			select {
			case ad.alertChan <- alert:
			default:
				log.Printf("Warning: alert channel full, dropping alert for %s/%s", key.ServiceName, key.Operation)
			}
			return alert
		}
	}

	return nil
}

func (ad *AnomalyDetector) shouldSendAlert(key OperationKey, severity string) bool {
	ad.cooldownMu.Lock()
	defer ad.cooldownMu.Unlock()

	alertKey := fmt.Sprintf("%s:%s:%s:%s", key.ServiceName, key.Operation, key.Protocol, severity)
	lastSent, exists := ad.cooldown[alertKey]

	if !exists || time.Since(lastSent) > time.Duration(ad.config.CooldownSeconds)*time.Second {
		ad.cooldown[alertKey] = time.Now()
		return true
	}

	return false
}

func (ad *AnomalyDetector) alertSender() {
	client := &http.Client{
		Timeout: time.Duration(ad.config.AlertManager.TimeoutMs) * time.Millisecond,
	}

	for {
		select {
		case <-ad.stopChan:
			return
		case alert := <-ad.alertChan:
			ad.sendAlertManager(client, alert)
		}
	}
}

func (ad *AnomalyDetector) sendAlertManager(client *http.Client, alert *AnomalyAlert) {
	alerts := []map[string]interface{}{
		{
			"labels": map[string]string{
				"alertname":   "LatencyAnomaly",
				"severity":    alert.Severity,
				"service":     alert.ServiceName,
				"operation":   alert.Operation,
				"trace_id":    alert.TraceID,
				"span_id":     alert.SpanID,
				"anomaly_type": alert.AnomalyType,
			},
			"annotations": map[string]string{
				"description": alert.Description,
				"current":     fmt.Sprintf("%.2fms", alert.CurrentValue),
				"threshold":   fmt.Sprintf("%.2fms", alert.Threshold),
				"deviation":   fmt.Sprintf("%.1f%%", alert.Deviation),
			},
			"startsAt": alert.Timestamp.Format(time.RFC3339),
		},
	}

	payload, err := json.Marshal(alerts)
	if err != nil {
		log.Printf("Error marshaling alert: %v", err)
		return
	}

	url := ad.config.AlertManager.URL + "/api/v2/alerts"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Error creating alert request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending alert to AlertManager: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("AlertManager returned non-2xx status: %d", resp.StatusCode)
	}
}

func (ad *AnomalyDetector) statsCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ad.stopChan:
			return
		case <-ticker.C:
			ad.cleanupOldStats()
			ad.cleanupOldCooldown()
		}
	}
}

func (ad *AnomalyDetector) cleanupOldStats() {
	ad.statsMutex.Lock()
	defer ad.statsMutex.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for key, stats := range ad.stats {
		if stats.LastUpdate.Before(cutoff) {
			delete(ad.stats, key)
		}
	}
}

func (ad *AnomalyDetector) cleanupOldCooldown() {
	ad.cooldownMu.Lock()
	defer ad.cooldownMu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for key, t := range ad.cooldown {
		if t.Before(cutoff) {
			delete(ad.cooldown, key)
		}
	}
}

func (ad *AnomalyDetector) GetStats(key OperationKey) (*LatencyStats, bool) {
	ad.statsMutex.RLock()
	defer ad.statsMutex.RUnlock()

	stats, exists := ad.stats[key]
	if !exists {
		return nil, false
	}

	statsCopy := *stats
	return &statsCopy, true
}

func (ad *AnomalyDetector) GetAllStats() map[OperationKey]LatencyStats {
	ad.statsMutex.RLock()
	defer ad.statsMutex.RUnlock()

	result := make(map[OperationKey]LatencyStats, len(ad.stats))
	for k, v := range ad.stats {
		result[k] = *v
	}
	return result
}

func (ad *AnomalyDetector) Stop() {
	close(ad.stopChan)
}

func (ad *AnomalyDetector) IsAnomaly(span *model.Span) bool {
	if span == nil || span.DurationMs <= 0 {
		return false
	}

	key := OperationKey{
		ServiceName: span.ServiceName,
		Operation:   span.Operation,
		Protocol:    span.Protocol,
	}

	ad.statsMutex.RLock()
	defer ad.statsMutex.RUnlock()

	stats, exists := ad.stats[key]
	if !exists || stats.Count < uint64(ad.config.MinSamples) {
		return false
	}

	threshold := stats.EWMA + ad.config.DeviationThreshold*math.Sqrt(stats.EWMAVar)
	return span.DurationMs > threshold
}
