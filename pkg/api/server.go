package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ebpf-tracing/ebpf-apm/pkg/config"
	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
	"github.com/ebpf-tracing/ebpf-apm/pkg/sampling"
	"github.com/ebpf-tracing/ebpf-apm/pkg/storage"
)

type Server struct {
	engine   *gin.Engine
	store    *storage.ClickHouseStore
	sampler  *sampling.DynamicSampler
	server   *http.Server
	cfg      *config.ServerConfig
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type TraceSearchRequest struct {
	ServiceName  string  `form:"service"`
	StartTime    int64   `form:"startTime"`
	EndTime      int64   `form:"endTime"`
	MinLatencyMs float64 `form:"minLatency"`
	MaxLatencyMs float64 `form:"maxLatency"`
	Protocol     string  `form:"protocol"`
	TraceID      string  `form:"traceId"`
	Limit        int     `form:"limit,default=20"`
	Offset       int     `form:"offset,default=0"`
}

func NewServer(cfg *config.ServerConfig, store *storage.ClickHouseStore, sampler *sampling.DynamicSampler) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery(), corsMiddleware(), loggingMiddleware())

	s := &Server{
		engine:  engine,
		store:   store,
		sampler: sampler,
		cfg:     cfg,
	}

	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	api := s.engine.Group("/api/v1")
	{
		api.GET("/trace/:traceId", s.getTrace)
		api.GET("/traces", s.searchTraces)
		api.GET("/services", s.getServices)
		api.GET("/services/:name/stats", s.getServiceStats)
		api.GET("/service-map", s.getServiceMap)
		api.GET("/sampling/stats", s.getSamplingStats)
		api.GET("/health", s.healthCheck)
	}

	s.engine.GET("/metrics", gin.WrapH(promhttp.Handler()))

	s.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, APIResponse{
			Code:    404,
			Message: "Not Found",
		})
	})
}

func (s *Server) getTrace(c *gin.Context) {
	traceID := c.Param("traceId")
	if traceID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Code:    400,
			Message: "traceId is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	trace, err := s.store.GetTraceByID(ctx, traceID)
	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{
			Code:    404,
			Message: fmt.Sprintf("Trace not found: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "success",
		Data:    trace,
	})
}

func (s *Server) searchTraces(c *gin.Context) {
	var req TraceSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Code:    400,
			Message: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	query := &model.TraceQuery{
		TraceID:     req.TraceID,
		ServiceName: req.ServiceName,
		Protocol:    req.Protocol,
		Limit:       req.Limit,
		Offset:      req.Offset,
	}

	if req.StartTime > 0 {
		t := time.UnixMilli(req.StartTime)
		query.StartTime = &t
	}
	if req.EndTime > 0 {
		t := time.UnixMilli(req.EndTime)
		query.EndTime = &t
	}
	if req.MinLatencyMs > 0 {
		query.MinLatencyMs = &req.MinLatencyMs
	}
	if req.MaxLatencyMs > 0 {
		query.MaxLatencyMs = &req.MaxLatencyMs
	}

	if query.StartTime == nil {
		t := time.Now().Add(-24 * time.Hour)
		query.StartTime = &t
	}
	if query.EndTime == nil {
		t := time.Now()
		query.EndTime = &t
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	traces, err := s.store.QueryTraces(ctx, query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Code:    500,
			Message: fmt.Sprintf("Query failed: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "success",
		Data: gin.H{
			"traces": traces,
			"total":  len(traces),
			"limit":  req.Limit,
			"offset": req.Offset,
		},
	})
}

func (s *Server) getServices(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	services, err := s.store.GetServices(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Code:    500,
			Message: fmt.Sprintf("Failed to get services: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "success",
		Data:    services,
	})
}

func (s *Server) getServiceStats(c *gin.Context) {
	serviceName := c.Param("name")
	if serviceName == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Code:    400,
			Message: "service name is required",
		})
		return
	}

	startTimeStr := c.DefaultQuery("startTime", strconv.FormatInt(time.Now().Add(-1*time.Hour).UnixMilli(), 10))
	endTimeStr := c.DefaultQuery("endTime", strconv.FormatInt(time.Now().UnixMilli(), 10))

	startTime, _ := strconv.ParseInt(startTimeStr, 10, 64)
	endTime, _ := strconv.ParseInt(endTimeStr, 10, 64)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	stats, err := s.store.GetServiceStats(ctx, serviceName, time.UnixMilli(startTime), time.UnixMilli(endTime))
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Code:    500,
			Message: fmt.Sprintf("Failed to get service stats: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "success",
		Data:    stats,
	})
}

func (s *Server) getServiceMap(c *gin.Context) {
	startTimeStr := c.DefaultQuery("startTime", strconv.FormatInt(time.Now().Add(-1*time.Hour).UnixMilli(), 10))
	endTimeStr := c.DefaultQuery("endTime", strconv.FormatInt(time.Now().UnixMilli(), 10))

	startTime, _ := strconv.ParseInt(startTimeStr, 10, 64)
	endTime, _ := strconv.ParseInt(endTimeStr, 10, 64)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	serviceMap, err := s.store.GetServiceMap(ctx, time.UnixMilli(startTime), time.UnixMilli(endTime))
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Code:    500,
			Message: fmt.Sprintf("Failed to get service map: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "success",
		Data:    serviceMap,
	})
}

func (s *Server) getSamplingStats(c *gin.Context) {
	stats := s.sampler.Stats()
	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "success",
		Data:    stats,
	})
}

func (s *Server) healthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	services, err := s.store.GetServices(ctx)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, APIResponse{
			Code:    503,
			Message: fmt.Sprintf("ClickHouse not healthy: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Code:    200,
		Message: "healthy",
		Data: gin.H{
			"services_count": len(services),
			"timestamp":      time.Now().Unix(),
		},
	})
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.HTTPPort)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.engine,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("API server starting on %s", addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("Shutting down API server...")
	return s.server.Shutdown(ctx)
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()

		log.Printf("[HTTP] %s %s %s %d %v", method, path, clientIP, statusCode, latency)
	}
}

func (r *APIResponse) String() string {
	data, _ := json.Marshal(r)
	return string(data)
}
