package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics("test_namespace")
	if m == nil {
		t.Fatal("Expected metrics instance, got nil")
	}

	// Test that all metric fields are initialized
	if m.RequestsTotal == nil {
		t.Error("RequestsTotal should be initialized")
	}
	if m.RequestDuration == nil {
		t.Error("RequestDuration should be initialized")
	}
	if m.RequestsInFlight == nil {
		t.Error("RequestsInFlight should be initialized")
	}
	if m.StorageOpsTotal == nil {
		t.Error("StorageOpsTotal should be initialized")
	}
	if m.CacheHits == nil {
		t.Error("CacheHits should be initialized")
	}
}

func TestNewMetrics_DefaultNamespace(t *testing.T) {
	m := NewMetrics("")
	if m == nil {
		t.Fatal("Expected metrics instance, got nil")
	}

	// Should use default namespace
	if m.RequestsTotal == nil {
		t.Error("RequestsTotal should be initialized with default namespace")
	}
}

func TestNewMetrics_Singleton(t *testing.T) {
	m1 := NewMetrics("test")
	m2 := NewMetrics("test")
	
	// Should return the same instance due to singleton pattern
	if m1 != m2 {
		t.Error("NewMetrics should return the same instance (singleton)")
	}
}

func TestIncRequest(t *testing.T) {
	m := NewMetrics("test")
	
	// Record initial count
	initialCount := m.requestCount
	
	m.IncRequest("GET", "test-bucket", "200", "GetObject")
	
	// Check that atomic counter was incremented
	if m.requestCount != initialCount+1 {
		t.Errorf("Expected request count %d, got %d", initialCount+1, m.requestCount)
	}
}

func TestIncError(t *testing.T) {
	m := NewMetrics("test")
	
	initialCount := m.errorCount
	
	m.IncError()
	
	if m.errorCount != initialCount+1 {
		t.Errorf("Expected error count %d, got %d", initialCount+1, m.errorCount)
	}
}

func TestAddBytesTransferred(t *testing.T) {
	m := NewMetrics("test")
	
	initialBytes := m.bytesTransferred
	addedBytes := uint64(1024)
	
	m.AddBytesTransferred(addedBytes)
	
	if m.bytesTransferred != initialBytes+addedBytes {
		t.Errorf("Expected bytes transferred %d, got %d", initialBytes+addedBytes, m.bytesTransferred)
	}
}

func TestObserveRequestDuration(t *testing.T) {
	m := NewMetrics("test")
	
	// This should not panic
	m.ObserveRequestDuration("GET", "test-bucket", "GetObject", 100*time.Millisecond)
}

func TestObserveResponseSize(t *testing.T) {
	m := NewMetrics("test")
	
	// This should not panic
	m.ObserveResponseSize("GET", "test-bucket", "GetObject", 1024)
}

func TestStorageMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test storage operation metrics
	m.IncStorageOp("s3", "GetObject", "success")
	m.ObserveStorageOpDuration("s3", "GetObject", 50*time.Millisecond)
	m.IncStorageError("s3", "GetObject", "network_error")
}

func TestCacheMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test cache metrics
	m.IncCacheHit("object_cache")
	m.IncCacheMiss("object_cache")
	m.SetCacheSize(1024*1024) // 1MB
}

func TestRateLimitMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test rate limit metrics
	m.IncRateLimit("request_rate", "blocked")
	m.IncConcurrencyLimit("rejected")
}

func TestKMSMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test KMS metrics
	m.IncKMSOperation("encrypt", "success")
	m.ObserveKMSOperationDuration("encrypt", 10*time.Millisecond)
	m.IncKMSError("decrypt", "invalid_key")
	m.IncKMSCacheHit("data_key")
	m.IncKMSCacheMiss("data_key")
	m.SetKMSDataKeysActive(5)
	m.IncKMSKeyValidation("valid")
}

func TestAuthMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test authentication metrics
	m.IncAuthAttempt("aws_v4")
	m.IncAuthFailure("aws_v4", "invalid_signature")
	m.ObserveAuthDuration("aws_v4", 5*time.Millisecond)
	m.SetAuthTokensActive(10)
	m.IncAuthTokenValidation("valid")
}

func TestDataTransferMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test data transfer metrics
	m.AddDataUpload("test-bucket", "PutObject", 1024)
	m.AddDataDownload("test-bucket", "GetObject", 2048)
	m.ObserveDataTransferDuration("upload", "test-bucket", 100*time.Millisecond)
	m.SetDataTransferRate("upload", "test-bucket", 10240) // 10KB/s
}

func TestConnectionPoolMetrics(t *testing.T) {
	m := NewMetrics("test")
	
	// Test connection pool metrics
	m.SetConnectionsActive("http", 5)
	m.SetConnectionsIdle("http", 2)
	m.ObserveConnectionWaitTime("http", 10*time.Millisecond)
	m.IncConnectionsCreated("http")
	m.IncConnectionsDestroyed("http", "timeout")
}

func TestGetStats(t *testing.T) {
	m := NewMetrics("test")
	
	// Add some test data
	m.IncRequest("GET", "test", "200", "GetObject")
	m.IncError()
	m.AddBytesTransferred(1024)
	
	// Wait a moment for elapsed time
	time.Sleep(10 * time.Millisecond)
	
	stats := m.GetStats()
	
	if stats.TotalRequests == 0 {
		t.Error("Expected non-zero total requests")
	}
	
	if stats.TotalErrors == 0 {
		t.Error("Expected non-zero total errors")
	}
	
	if stats.BytesTransferred == 0 {
		t.Error("Expected non-zero bytes transferred")
	}
	
	if stats.RequestsPerSec < 0 {
		t.Error("Expected non-negative requests per second")
	}
	
	if stats.ErrorRate < 0 || stats.ErrorRate > 1 {
		t.Error("Expected error rate between 0 and 1")
	}
	
	if stats.Throughput < 0 {
		t.Error("Expected non-negative throughput")
	}
	
	if stats.Uptime <= 0 {
		t.Error("Expected positive uptime")
	}
}

func TestResetStats(t *testing.T) {
	m := NewMetrics("test")
	
	// Add some data
	m.IncRequest("GET", "test", "200", "GetObject")
	m.IncError()
	m.AddBytesTransferred(1024)
	
	// Reset stats
	m.ResetStats()
	
	stats := m.GetStats()
	
	if stats.TotalRequests != 0 {
		t.Errorf("Expected zero requests after reset, got %d", stats.TotalRequests)
	}
	
	if stats.TotalErrors != 0 {
		t.Errorf("Expected zero errors after reset, got %d", stats.TotalErrors)
	}
	
	if stats.BytesTransferred != 0 {
		t.Errorf("Expected zero bytes transferred after reset, got %d", stats.BytesTransferred)
	}
}

func TestMiddleware(t *testing.T) {
	m := NewMetrics("test")
	
	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})
	
	// Wrap with metrics middleware
	wrappedHandler := m.Middleware()(handler)
	
	// Create test request
	req := httptest.NewRequest("GET", "/test-bucket/test-object", nil)
	rec := httptest.NewRecorder()
	
	// Record initial counts
	initialRequests := m.requestCount
	initialBytes := m.bytesTransferred
	
	// Execute request
	wrappedHandler.ServeHTTP(rec, req)
	
	// Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	
	if rec.Body.String() != "test response" {
		t.Errorf("Expected 'test response', got '%s'", rec.Body.String())
	}
	
	// Verify metrics were recorded
	if m.requestCount != initialRequests+1 {
		t.Errorf("Expected request count to increment")
	}
	
	if m.bytesTransferred <= initialBytes {
		t.Error("Expected bytes transferred to increase")
	}
}

func TestMiddleware_ErrorResponse(t *testing.T) {
	m := NewMetrics("test")
	
	// Create a handler that returns an error
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	
	wrappedHandler := m.Middleware()(handler)
	
	req := httptest.NewRequest("GET", "/test-bucket/test-object", nil)
	rec := httptest.NewRecorder()
	
	initialErrors := m.errorCount
	
	wrappedHandler.ServeHTTP(rec, req)
	
	// Verify error was recorded
	if m.errorCount != initialErrors+1 {
		t.Error("Expected error count to increment for 500 response")
	}
}

func TestMiddleware_Upload(t *testing.T) {
	m := NewMetrics("test")
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	wrappedHandler := m.Middleware()(handler)
	
	// Create PUT request with body
	body := bytes.NewReader([]byte("test upload data"))
	req := httptest.NewRequest("PUT", "/test-bucket/test-object", body)
	req.ContentLength = int64(body.Len())
	rec := httptest.NewRecorder()
	
	wrappedHandler.ServeHTTP(rec, req)
	
	// Should have tracked upload metrics
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}
	
	// Test WriteHeader
	rw.WriteHeader(http.StatusCreated)
	if rw.statusCode != http.StatusCreated {
		t.Errorf("Expected status code 201, got %d", rw.statusCode)
	}
	
	// Test Write
	testData := []byte("test data")
	n, err := rw.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}
	
	if rw.bytesWritten != int64(len(testData)) {
		t.Errorf("Expected bytes written %d, got %d", len(testData), rw.bytesWritten)
	}
}

func TestExtractOperationAndBucket(t *testing.T) {
	tests := []struct {
		method    string
		path      string
		wantOp    string
		wantBucket string
	}{
		{"GET", "/", "ListBuckets", ""},
		{"GET", "/bucket", "ListObjects", "bucket"},
		{"GET", "/bucket/object", "GetObject", "bucket"},
		{"PUT", "/bucket", "CreateBucket", "bucket"},
		{"PUT", "/bucket/object", "PutObject", "bucket"},
		{"DELETE", "/bucket", "DeleteBucket", "bucket"},
		{"DELETE", "/bucket/object", "DeleteObject", "bucket"},
		{"HEAD", "/bucket", "HeadBucket", "bucket"},
		{"HEAD", "/bucket/object", "HeadObject", "bucket"},
		{"POST", "/bucket/object", "PostObject", "bucket"},
		{"PATCH", "/bucket/object", "Unknown", "bucket"},
	}
	
	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			gotOp, gotBucket := extractOperationAndBucket(req)
			
			if gotOp != tt.wantOp {
				t.Errorf("Expected operation %s, got %s", tt.wantOp, gotOp)
			}
			
			if gotBucket != tt.wantBucket {
				t.Errorf("Expected bucket %s, got %s", tt.wantBucket, gotBucket)
			}
		})
	}
}

func TestHandler(t *testing.T) {
	m := NewMetrics("test")
	
	handler := m.Handler()
	if handler == nil {
		t.Error("Handler should not be nil")
	}
	
	// Test that it returns a valid HTTP handler
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	
	handler.ServeHTTP(rec, req)
	
	// Should return metrics in Prometheus format
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	
	body := rec.Body.String()
	if !strings.Contains(body, "# HELP") {
		t.Error("Response should contain Prometheus metrics format")
	}
}

func TestStatsHandler(t *testing.T) {
	m := NewMetrics("test")
	
	// Add some test data
	m.IncRequest("GET", "test", "200", "GetObject")
	m.IncError()
	m.AddBytesTransferred(1024)
	
	handler := m.StatsHandler()
	
	req := httptest.NewRequest("GET", "/stats", nil)
	rec := httptest.NewRecorder()
	
	handler.ServeHTTP(rec, req)
	
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected content type application/json, got %s", contentType)
	}
	
	body := rec.Body.String()
	if !strings.Contains(body, "total_requests") {
		t.Error("Response should contain total_requests field")
	}
	
	if !strings.Contains(body, "total_errors") {
		t.Error("Response should contain total_errors field")
	}
	
	if !strings.Contains(body, "bytes_transferred") {
		t.Error("Response should contain bytes_transferred field")
	}
}

func TestStats_JSON_Fields(t *testing.T) {
	stats := Stats{
		TotalRequests:    100,
		TotalErrors:      5,
		BytesTransferred: 1024000,
		RequestsPerSec:   10.5,
		ErrorRate:        0.05,
		Throughput:       1024.5,
		Uptime:           5 * time.Minute,
	}
	
	if stats.TotalRequests != 100 {
		t.Errorf("Expected TotalRequests 100, got %d", stats.TotalRequests)
	}
	
	if stats.ErrorRate != 0.05 {
		t.Errorf("Expected ErrorRate 0.05, got %f", stats.ErrorRate)
	}
	
	if stats.Uptime != 5*time.Minute {
		t.Errorf("Expected Uptime 5m, got %v", stats.Uptime)
	}
}

func BenchmarkIncRequest(b *testing.B) {
	m := NewMetrics("bench")
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.IncRequest("GET", "bucket", "200", "GetObject")
		}
	})
}

func BenchmarkIncError(b *testing.B) {
	m := NewMetrics("bench")
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.IncError()
		}
	})
}

func BenchmarkAddBytesTransferred(b *testing.B) {
	m := NewMetrics("bench")
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.AddBytesTransferred(1024)
		}
	})
}

func BenchmarkGetStats(b *testing.B) {
	m := NewMetrics("bench")
	
	// Add some data
	m.IncRequest("GET", "bucket", "200", "GetObject")
	m.IncError()
	m.AddBytesTransferred(1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.GetStats()
	}
}

func BenchmarkMiddleware(b *testing.B) {
	m := NewMetrics("bench")
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})
	
	wrappedHandler := m.Middleware()(handler)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/bucket/object", nil)
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)
	}
}