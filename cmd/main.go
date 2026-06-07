package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/ebpf-tracing/ebpf-apm/pkg/api"
	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	ebpfpkg "github.com/ebpf-tracing/ebpf-apm/pkg/ebpf"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
	"github.com/ebpf-tracing/ebpf-apm/pkg/sampling"
	"github.com/ebpf-tracing/ebpf-apm/pkg/storage"
	"github.com/ebpf-tracing/ebpf-apm/pkg/trace"
)

var (
	configPath  = flag.String("config", "config.yaml", "Path to config file")
	enableEBPF  = flag.Bool("enable-ebpf", true, "Enable eBPF tracing")
	enableAPI   = flag.Bool("enable-api", true, "Enable REST API")
	initSchema  = flag.Bool("init-schema", false, "Initialize ClickHouse schema")
)

type App struct {
	tracer     *ebpfpkg.Tracer
	correlator *trace.Correlator
	sampler    *sampling.TraceLevelSampler
	dynamicSampler *sampling.DynamicSampler
	store      *storage.ClickHouseStore
	apiServer  *api.Server
	ctx        context.Context
	cancel     context.CancelFunc
}

func main() {
	flag.Parse()

	if runtime.GOOS != "linux" {
		log.Fatal("This program must be run on Linux")
	}

	if os.Getuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	if err := config.Load(*configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	app := &App{}
	app.ctx, app.cancel = context.WithCancel(context.Background())

	var err error
	app.store, err = storage.NewClickHouseStore(&config.AppConfig.ClickHouse)
	if err != nil {
		log.Fatalf("Failed to create ClickHouse store: %v", err)
	}
	defer app.store.Close()

	if *initSchema {
		log.Println("Initializing ClickHouse schema...")
		if err := app.store.InitSchema(app.ctx); err != nil {
			log.Fatalf("Failed to initialize schema: %v", err)
		}
		log.Println("Schema initialized successfully")
		return
	}

	app.dynamicSampler = sampling.NewDynamicSampler(&config.AppConfig.Sampling)
	app.sampler = sampling.NewTraceLevelSampler(app.dynamicSampler)

	app.correlator = trace.NewCorrelator()
	app.correlator.SetSpanHandler(app.handleSpan)

	if *enableEBPF {
		app.tracer, err = ebpfpkg.NewTracer(&config.AppConfig.EBPF)
		if err != nil {
			log.Fatalf("Failed to create eBPF tracer: %v", err)
		}
		app.tracer.SetEventHandler(app.correlator.ProcessEvent)

		if err := app.tracer.Start(app.ctx); err != nil {
			log.Fatalf("Failed to start eBPF tracer: %v", err)
		}
		defer app.tracer.Stop()

		log.Println("eBPF tracer started, capturing network events...")
	}

	if *enableAPI {
		app.apiServer = api.NewServer(&config.AppConfig.Server, app.store, app.dynamicSampler)
		go func() {
			if err := app.apiServer.Start(); err != nil {
				log.Printf("API server error: %v", err)
			}
		}()
		defer app.apiServer.Stop()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	log.Println("Application started successfully")
	log.Printf("Press Ctrl+C to stop")

	if *enableEBPF {
		go app.eventLoop()
	}

	sig := <-sigChan
	log.Printf("Received signal: %v, shutting down...", sig)
	app.cancel()
}

func (app *App) eventLoop() {
	for {
		select {
		case <-app.ctx.Done():
			return
		case event, ok := <-app.tracer.Events():
			if !ok {
				return
			}
			app.correlator.ProcessEvent(event)
		}
	}
}

func (app *App) handleSpan(span *model.Span) {
	if !app.sampler.ShouldSample(span) {
		return
	}

	storeCtx, cancel := context.WithTimeout(app.ctx, 5*time.Second)
	defer cancel()

	if err := app.store.SaveSpan(storeCtx, span); err != nil {
		log.Printf("Warning: failed to save span: %v", err)
	}

	stats := app.dynamicSampler.Stats()
	if stats.TotalCount%1000 == 0 {
		log.Printf("Sampling stats: total=%d, sampled=%d (%.2f%%), high_latency=%d, low_latency=%d",
			stats.TotalCount, stats.SampledCount, stats.OverallSampleRate*100,
			stats.HighLatencyCount, stats.LowLatencyCount)
	}
}
