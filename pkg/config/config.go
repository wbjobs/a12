package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig       `mapstructure:"server"`
	ClickHouse  ClickHouseConfig   `mapstructure:"clickhouse"`
	Sampling    SamplingConfig     `mapstructure:"sampling"`
	EBPF        EBPFConfig         `mapstructure:"ebpf"`
	Protocols   ProtocolsConfig    `mapstructure:"protocols"`
	Anomaly     AnomalyConfig      `mapstructure:"anomaly"`
	Compression CompressionConfig  `mapstructure:"compression"`
	FlameGraph  FlameGraphConfig   `mapstructure:"flamegraph"`
	Envoy       EnvoyConfig        `mapstructure:"envoy"`
}

type ServerConfig struct {
	HTTPPort int `mapstructure:"http_port"`
	GRPCPort int `mapstructure:"grpc_port"`
}

type ClickHouseConfig struct {
	Host          string `mapstructure:"host"`
	Port          int    `mapstructure:"port"`
	Database      string `mapstructure:"database"`
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"`
	MaxOpenConns  int    `mapstructure:"max_open_conns"`
	MaxIdleConns  int    `mapstructure:"max_idle_conns"`
	BatchSize     int    `mapstructure:"batch_size"`
	QueueCapacity int    `mapstructure:"queue_capacity"`
	FlushInterval int    `mapstructure:"flush_interval_seconds"`
	MaxRetries    int    `mapstructure:"max_retries"`
}

type SamplingConfig struct {
	HighLatencyThresholdMs int     `mapstructure:"high_latency_threshold_ms"`
	HighLatencySampleRate  float64 `mapstructure:"high_latency_sample_rate"`
	LowLatencySampleRate   float64 `mapstructure:"low_latency_sample_rate"`
}

type EBPFConfig struct {
	PerfBufferSize int `mapstructure:"perf_buffer_size"`
	PollTimeoutMs  int `mapstructure:"poll_timeout_ms"`
}

type ProtocolsConfig struct {
	HTTP  ProtocolConfig `mapstructure:"http"`
	GRPC  ProtocolConfig `mapstructure:"grpc"`
	Redis ProtocolConfig `mapstructure:"redis"`
}

type ProtocolConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Ports   []int  `mapstructure:"ports"`
}

var AppConfig *Config

func Load(configPath string) error {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	AppConfig = &Config{}
	if err := v.Unmarshal(AppConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

func (c *ClickHouseConfig) DSN() string {
	return fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s",
		c.Username, c.Password, c.Host, c.Port, c.Database)
}

type AnomalyConfig struct {
	Enabled            bool              `mapstructure:"enabled"`
	Alpha              float64           `mapstructure:"alpha"`
	DeviationThreshold float64           `mapstructure:"deviation_threshold"`
	MinSamples         int               `mapstructure:"min_samples"`
	CooldownSeconds    int               `mapstructure:"cooldown_seconds"`
	AlertManager       AlertManagerConfig `mapstructure:"alertmanager"`
}

type AlertManagerConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	URL       string `mapstructure:"url"`
	TimeoutMs int    `mapstructure:"timeout_ms"`
}

type CompressionConfig struct {
	Enabled             bool    `mapstructure:"enabled"`
	CompressionLevel    int     `mapstructure:"compression_level"`
	MaxCacheSize        int     `mapstructure:"max_cache_size"`
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`
}

type FlameGraphConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	DefaultWidth   int  `mapstructure:"default_width"`
	HeightPerFrame int  `mapstructure:"height_per_frame"`
	MaxDepth       int  `mapstructure:"max_depth"`
}

type EnvoyConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	DetectAllPorts bool `mapstructure:"detect_all_ports"`
}
