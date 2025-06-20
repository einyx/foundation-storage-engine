// Package metrics provides metrics collection and HTTP endpoints for monitoring.
package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all the metrics for the s3proxy
type Metrics struct {
	// Request metrics
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestsInFlight prometheus.Gauge
	ResponseSize     *prometheus.HistogramVec

	// Storage metrics
	StorageOpsTotal    *prometheus.CounterVec
	StorageOpsDuration *prometheus.HistogramVec
	StorageErrors      *prometheus.CounterVec

	// Cache metrics
	CacheHits   *prometheus.CounterVec
	CacheMisses *prometheus.CounterVec
	CacheSize   prometheus.Gauge

	// Rate limiting metrics
	RateLimitTotal   *prometheus.CounterVec
	ConcurrencyLimit *prometheus.CounterVec

	// System metrics
	GoroutineCount prometheus.Gauge
	MemoryUsage    prometheus.Gauge
	GCDuration     prometheus.Histogram

	// KMS metrics
	KMSOperationsTotal   *prometheus.CounterVec
	KMSOperationDuration *prometheus.HistogramVec
	KMSErrors            *prometheus.CounterVec
	KMSCacheHits         *prometheus.CounterVec
	KMSCacheMisses       *prometheus.CounterVec
	KMSDataKeysActive    prometheus.Gauge
	KMSKeyValidations    *prometheus.CounterVec

	// Authentication metrics
	AuthAttemptsTotal    *prometheus.CounterVec
	AuthFailuresTotal    *prometheus.CounterVec
	AuthDuration         *prometheus.HistogramVec
	AuthTokensActive     prometheus.Gauge
	AuthTokenValidations *prometheus.CounterVec

	// Data transfer metrics
	DataUploadBytes      *prometheus.CounterVec
	DataDownloadBytes    *prometheus.CounterVec
	DataTransferDuration *prometheus.HistogramVec
	DataTransferRate     *prometheus.GaugeVec

	// Connection pool metrics
	ConnectionsActive    *prometheus.GaugeVec
	ConnectionsIdle      *prometheus.GaugeVec
	ConnectionsWaitTime  *prometheus.HistogramVec
	ConnectionsCreated   *prometheus.CounterVec
	ConnectionsDestroyed *prometheus.CounterVec

	// Real-time stats (for fast access without Prometheus overhead)
	requestCount     uint64
	errorCount       uint64
	bytesTransferred uint64
	lastResetTime    time.Time
	mu               sync.RWMutex
}

// NewMetrics creates a new metrics instance
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "s3proxy"
	}

	return &Metrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "requests_total",
				Help:      "Total number of requests processed",
			},
			[]string{"method", "bucket", "status_code", "operation"},
		),

		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "request_duration_seconds",
				Help:      "Request duration in seconds",
				Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~32s
			},
			[]string{"method", "bucket", "operation"},
		),

		RequestsInFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "requests_in_flight",
				Help:      "Number of requests currently being processed",
			},
		),

		ResponseSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "response_size_bytes",
				Help:      "Response size in bytes",
				Buckets:   prometheus.ExponentialBuckets(1024, 4, 10), // 1KB to ~1GB
			},
			[]string{"method", "bucket", "operation"},
		),

		StorageOpsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "storage_operations_total",
				Help:      "Total number of storage backend operations",
			},
			[]string{"backend", "operation", "status"},
		),

		StorageOpsDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "storage_operation_duration_seconds",
				Help:      "Storage operation duration in seconds",
				Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
			},
			[]string{"backend", "operation"},
		),

		StorageErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "storage_errors_total",
				Help:      "Total number of storage errors",
			},
			[]string{"backend", "operation", "error_type"},
		),

		CacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"cache_type"},
		),

		CacheMisses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"cache_type"},
		),

		CacheSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "cache_size_bytes",
				Help:      "Current cache size in bytes",
			},
		),

		RateLimitTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "rate_limit_total",
				Help:      "Total number of rate limit events",
			},
			[]string{"limit_type", "action"},
		),

		ConcurrencyLimit: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "concurrency_limit_total",
				Help:      "Total number of concurrency limit events",
			},
			[]string{"action"},
		),

		GoroutineCount: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "goroutines_count",
				Help:      "Number of goroutines",
			},
		),

		MemoryUsage: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "memory_usage_bytes",
				Help:      "Memory usage in bytes",
			},
		),

		GCDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "gc_duration_seconds",
				Help:      "Garbage collection duration in seconds",
				Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 15),
			},
		),

		// KMS metrics
		KMSOperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "kms_operations_total",
				Help:      "Total number of KMS operations",
			},
			[]string{"operation", "status"},
		),

		KMSOperationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "kms_operation_duration_seconds",
				Help:      "KMS operation duration in seconds",
				Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
			},
			[]string{"operation"},
		),

		KMSErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "kms_errors_total",
				Help:      "Total number of KMS errors",
			},
			[]string{"operation", "error_type"},
		),

		KMSCacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "kms_cache_hits_total",
				Help:      "Total number of KMS cache hits",
			},
			[]string{"cache_type"},
		),

		KMSCacheMisses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "kms_cache_misses_total",
				Help:      "Total number of KMS cache misses",
			},
			[]string{"cache_type"},
		),

		KMSDataKeysActive: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "kms_data_keys_active",
				Help:      "Number of active data keys in cache",
			},
		),

		KMSKeyValidations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "kms_key_validations_total",
				Help:      "Total number of KMS key validations",
			},
			[]string{"status"},
		),

		// Authentication metrics
		AuthAttemptsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_attempts_total",
				Help:      "Total number of authentication attempts",
			},
			[]string{"method"},
		),

		AuthFailuresTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_failures_total",
				Help:      "Total number of authentication failures",
			},
			[]string{"method", "reason"},
		),

		AuthDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "auth_duration_seconds",
				Help:      "Authentication duration in seconds",
				Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 10), // 0.1ms to ~100ms
			},
			[]string{"method"},
		),

		AuthTokensActive: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "auth_tokens_active",
				Help:      "Number of active authentication tokens",
			},
		),

		AuthTokenValidations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_token_validations_total",
				Help:      "Total number of token validations",
			},
			[]string{"status"},
		),

		// Data transfer metrics
		DataUploadBytes: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "data_upload_bytes_total",
				Help:      "Total bytes uploaded",
			},
			[]string{"bucket", "operation"},
		),

		DataDownloadBytes: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "data_download_bytes_total",
				Help:      "Total bytes downloaded",
			},
			[]string{"bucket", "operation"},
		),

		DataTransferDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "data_transfer_duration_seconds",
				Help:      "Data transfer duration in seconds",
				Buckets:   prometheus.ExponentialBuckets(0.01, 2, 15), // 10ms to ~5min
			},
			[]string{"direction", "bucket"},
		),

		DataTransferRate: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "data_transfer_rate_bytes_per_sec",
				Help:      "Current data transfer rate in bytes per second",
			},
			[]string{"direction", "bucket"},
		),

		// Connection pool metrics
		ConnectionsActive: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "connections_active",
				Help:      "Number of active connections",
			},
			[]string{"pool"},
		),

		ConnectionsIdle: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "connections_idle",
				Help:      "Number of idle connections",
			},
			[]string{"pool"},
		),

		ConnectionsWaitTime: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "connections_wait_time_seconds",
				Help:      "Time spent waiting for a connection",
				Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 12), // 0.1ms to ~400ms
			},
			[]string{"pool"},
		),

		ConnectionsCreated: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "connections_created_total",
				Help:      "Total number of connections created",
			},
			[]string{"pool"},
		),

		ConnectionsDestroyed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "connections_destroyed_total",
				Help:      "Total number of connections destroyed",
			},
			[]string{"pool", "reason"},
		),

		lastResetTime: time.Now(),
	}
}

// IncRequest increments request counter
func (m *Metrics) IncRequest(method, bucket, statusCode, operation string) {
	m.RequestsTotal.WithLabelValues(method, bucket, statusCode, operation).Inc()
	atomic.AddUint64(&m.requestCount, 1)
}

// IncError increments error counter
func (m *Metrics) IncError() {
	atomic.AddUint64(&m.errorCount, 1)
}

// AddBytesTransferred adds to bytes transferred counter
func (m *Metrics) AddBytesTransferred(bytes uint64) {
	atomic.AddUint64(&m.bytesTransferred, bytes)
}

// ObserveRequestDuration observes request duration
func (m *Metrics) ObserveRequestDuration(method, bucket, operation string, duration time.Duration) {
	m.RequestDuration.WithLabelValues(method, bucket, operation).Observe(duration.Seconds())
}

// ObserveResponseSize observes response size
func (m *Metrics) ObserveResponseSize(method, bucket, operation string, size int64) {
	m.ResponseSize.WithLabelValues(method, bucket, operation).Observe(float64(size))
}

// IncStorageOp increments storage operation counter
func (m *Metrics) IncStorageOp(backend, operation, status string) {
	m.StorageOpsTotal.WithLabelValues(backend, operation, status).Inc()
}

// ObserveStorageOpDuration observes storage operation duration
func (m *Metrics) ObserveStorageOpDuration(backend, operation string, duration time.Duration) {
	m.StorageOpsDuration.WithLabelValues(backend, operation).Observe(duration.Seconds())
}

// IncStorageError increments storage error counter
func (m *Metrics) IncStorageError(backend, operation, errorType string) {
	m.StorageErrors.WithLabelValues(backend, operation, errorType).Inc()
}

// IncCacheHit increments cache hit counter
func (m *Metrics) IncCacheHit(cacheType string) {
	m.CacheHits.WithLabelValues(cacheType).Inc()
}

// IncCacheMiss increments cache miss counter
func (m *Metrics) IncCacheMiss(cacheType string) {
	m.CacheMisses.WithLabelValues(cacheType).Inc()
}

// SetCacheSize sets current cache size
func (m *Metrics) SetCacheSize(bytes float64) {
	m.CacheSize.Set(bytes)
}

// IncRateLimit increments rate limit counter
func (m *Metrics) IncRateLimit(limitType, action string) {
	m.RateLimitTotal.WithLabelValues(limitType, action).Inc()
}

// IncConcurrencyLimit increments concurrency limit counter
func (m *Metrics) IncConcurrencyLimit(action string) {
	m.ConcurrencyLimit.WithLabelValues(action).Inc()
}

// KMS metrics helpers

// IncKMSOperation increments KMS operation counter
func (m *Metrics) IncKMSOperation(operation, status string) {
	m.KMSOperationsTotal.WithLabelValues(operation, status).Inc()
}

// ObserveKMSOperationDuration observes KMS operation duration
func (m *Metrics) ObserveKMSOperationDuration(operation string, duration time.Duration) {
	m.KMSOperationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// IncKMSError increments KMS error counter
func (m *Metrics) IncKMSError(operation, errorType string) {
	m.KMSErrors.WithLabelValues(operation, errorType).Inc()
}

// IncKMSCacheHit increments KMS cache hit counter
func (m *Metrics) IncKMSCacheHit(cacheType string) {
	m.KMSCacheHits.WithLabelValues(cacheType).Inc()
}

// IncKMSCacheMiss increments KMS cache miss counter
func (m *Metrics) IncKMSCacheMiss(cacheType string) {
	m.KMSCacheMisses.WithLabelValues(cacheType).Inc()
}

// SetKMSDataKeysActive sets the number of active data keys
func (m *Metrics) SetKMSDataKeysActive(count float64) {
	m.KMSDataKeysActive.Set(count)
}

// IncKMSKeyValidation increments key validation counter
func (m *Metrics) IncKMSKeyValidation(status string) {
	m.KMSKeyValidations.WithLabelValues(status).Inc()
}

// Authentication metrics helpers

// IncAuthAttempt increments authentication attempt counter
func (m *Metrics) IncAuthAttempt(method string) {
	m.AuthAttemptsTotal.WithLabelValues(method).Inc()
}

// IncAuthFailure increments authentication failure counter
func (m *Metrics) IncAuthFailure(method, reason string) {
	m.AuthFailuresTotal.WithLabelValues(method, reason).Inc()
}

// ObserveAuthDuration observes authentication duration
func (m *Metrics) ObserveAuthDuration(method string, duration time.Duration) {
	m.AuthDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// SetAuthTokensActive sets the number of active auth tokens
func (m *Metrics) SetAuthTokensActive(count float64) {
	m.AuthTokensActive.Set(count)
}

// IncAuthTokenValidation increments token validation counter
func (m *Metrics) IncAuthTokenValidation(status string) {
	m.AuthTokenValidations.WithLabelValues(status).Inc()
}

// Data transfer metrics helpers

// AddDataUpload adds to upload bytes counter
func (m *Metrics) AddDataUpload(bucket, operation string, bytes int64) {
	m.DataUploadBytes.WithLabelValues(bucket, operation).Add(float64(bytes))
}

// AddDataDownload adds to download bytes counter
func (m *Metrics) AddDataDownload(bucket, operation string, bytes int64) {
	m.DataDownloadBytes.WithLabelValues(bucket, operation).Add(float64(bytes))
}

// ObserveDataTransferDuration observes data transfer duration
func (m *Metrics) ObserveDataTransferDuration(direction, bucket string, duration time.Duration) {
	m.DataTransferDuration.WithLabelValues(direction, bucket).Observe(duration.Seconds())
}

// SetDataTransferRate sets current data transfer rate
func (m *Metrics) SetDataTransferRate(direction, bucket string, bytesPerSec float64) {
	m.DataTransferRate.WithLabelValues(direction, bucket).Set(bytesPerSec)
}

// Connection pool metrics helpers

// SetConnectionsActive sets the number of active connections
func (m *Metrics) SetConnectionsActive(pool string, count float64) {
	m.ConnectionsActive.WithLabelValues(pool).Set(count)
}

// SetConnectionsIdle sets the number of idle connections
func (m *Metrics) SetConnectionsIdle(pool string, count float64) {
	m.ConnectionsIdle.WithLabelValues(pool).Set(count)
}

// ObserveConnectionWaitTime observes connection wait time
func (m *Metrics) ObserveConnectionWaitTime(pool string, duration time.Duration) {
	m.ConnectionsWaitTime.WithLabelValues(pool).Observe(duration.Seconds())
}

// IncConnectionsCreated increments connections created counter
func (m *Metrics) IncConnectionsCreated(pool string) {
	m.ConnectionsCreated.WithLabelValues(pool).Inc()
}

// IncConnectionsDestroyed increments connections destroyed counter
func (m *Metrics) IncConnectionsDestroyed(pool, reason string) {
	m.ConnectionsDestroyed.WithLabelValues(pool, reason).Inc()
}

// GetStats returns current statistics
func (m *Metrics) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	elapsed := time.Since(m.lastResetTime)
	requests := atomic.LoadUint64(&m.requestCount)
	errors := atomic.LoadUint64(&m.errorCount)
	bytes := atomic.LoadUint64(&m.bytesTransferred)

	return Stats{
		TotalRequests:    requests,
		TotalErrors:      errors,
		BytesTransferred: bytes,
		RequestsPerSec:   float64(requests) / elapsed.Seconds(),
		ErrorRate:        float64(errors) / float64(requests),
		Throughput:       float64(bytes) / elapsed.Seconds(),
		Uptime:           elapsed,
	}
}

// ResetStats resets the statistics counters
func (m *Metrics) ResetStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.StoreUint64(&m.requestCount, 0)
	atomic.StoreUint64(&m.errorCount, 0)
	atomic.StoreUint64(&m.bytesTransferred, 0)
	m.lastResetTime = time.Now()
}

// Stats holds performance statistics
type Stats struct {
	TotalRequests    uint64        `json:"total_requests"`
	TotalErrors      uint64        `json:"total_errors"`
	BytesTransferred uint64        `json:"bytes_transferred"`
	RequestsPerSec   float64       `json:"requests_per_sec"`
	ErrorRate        float64       `json:"error_rate"`
	Throughput       float64       `json:"throughput_bytes_per_sec"`
	Uptime           time.Duration `json:"uptime"`
}

// Middleware returns a middleware that collects HTTP metrics
func (m *Metrics) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Increment in-flight requests
			m.RequestsInFlight.Inc()
			defer m.RequestsInFlight.Dec()

			// Wrap response writer to capture status and size
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Extract operation and bucket from path
			operation, bucket := extractOperationAndBucket(r)

			// Track request body size for uploads
			var requestBodySize int64
			if r.ContentLength > 0 {
				requestBodySize = r.ContentLength
			}

			// Call next handler
			next.ServeHTTP(wrapped, r)

			// Record metrics
			duration := time.Since(start)
			statusCode := strconv.Itoa(wrapped.statusCode)

			m.IncRequest(r.Method, bucket, statusCode, operation)
			m.ObserveRequestDuration(r.Method, bucket, operation, duration)
			m.ObserveResponseSize(r.Method, bucket, operation, wrapped.bytesWritten)

			// Track data transfer metrics
			if wrapped.statusCode < 400 {
				// Track uploads (PUT, POST operations)
				if (operation == "PutObject" || operation == "PostObject") && requestBodySize > 0 {
					m.AddDataUpload(bucket, operation, requestBodySize)
					m.ObserveDataTransferDuration("upload", bucket, duration)
					if duration.Seconds() > 0 {
						rate := float64(requestBodySize) / duration.Seconds()
						m.SetDataTransferRate("upload", bucket, rate)
					}
				}

				// Track downloads (GET operations)
				if operation == "GetObject" && wrapped.bytesWritten > 0 {
					m.AddDataDownload(bucket, operation, wrapped.bytesWritten)
					m.ObserveDataTransferDuration("download", bucket, duration)
					if duration.Seconds() > 0 {
						rate := float64(wrapped.bytesWritten) / duration.Seconds()
						m.SetDataTransferRate("download", bucket, rate)
					}
				}
			}

			if wrapped.bytesWritten > 0 {
				m.AddBytesTransferred(uint64(wrapped.bytesWritten))
			}

			if wrapped.statusCode >= 400 {
				m.IncError()
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture metrics
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// extractOperationAndBucket extracts S3 operation and bucket from request
func extractOperationAndBucket(r *http.Request) (operation, bucket string) {
	path := r.URL.Path
	if path == "/" || path == "" {
		return "ListBuckets", ""
	}

	// Remove leading slash
	if path[0] == '/' {
		path = path[1:]
	}

	parts := strings.SplitN(path, "/", 2)
	bucket = parts[0]

	// Determine operation based on method and path
	switch r.Method {
	case "GET":
		if len(parts) == 1 {
			return "ListObjects", bucket
		}
		return "GetObject", bucket
	case "PUT":
		if len(parts) == 1 {
			return "CreateBucket", bucket
		}
		return "PutObject", bucket
	case "DELETE":
		if len(parts) == 1 {
			return "DeleteBucket", bucket
		}
		return "DeleteObject", bucket
	case "HEAD":
		if len(parts) == 1 {
			return "HeadBucket", bucket
		}
		return "HeadObject", bucket
	case "POST":
		return "PostObject", bucket
	default:
		return "Unknown", bucket
	}
}

// Handler returns HTTP handler for metrics endpoint
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// StatsHandler returns HTTP handler for JSON stats endpoint
func (m *Metrics) StatsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := m.GetStats()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Simple JSON encoding without external dependencies
		_, _ = fmt.Fprintf(w, `{
  "total_requests": %d,
  "total_errors": %d,
  "bytes_transferred": %d,
  "requests_per_sec": %.2f,
  "error_rate": %.4f,
  "throughput_bytes_per_sec": %.2f,
  "uptime_seconds": %.0f
}`, stats.TotalRequests, stats.TotalErrors, stats.BytesTransferred,
			stats.RequestsPerSec, stats.ErrorRate, stats.Throughput, stats.Uptime.Seconds())
	})
}
