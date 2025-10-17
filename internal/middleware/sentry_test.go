package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
)

func TestSentryMiddleware(t *testing.T) {
	// Initialize Sentry for testing (with noop transport)
	err := sentry.Init(sentry.ClientOptions{
		Dsn:     "https://test@sentry.example.com/1",
		Debug:   false,
		Release: "test@1.0.0",
		Transport: &mockTransport{},
	})
	if err != nil {
		t.Fatalf("Failed to init Sentry: %v", err)
	}
	defer sentry.Flush(time.Second)

	middleware := SentryMiddleware(false)

	t.Run("success_request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})

		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}

		if rec.Body.String() != "OK" {
			t.Errorf("Expected body 'OK', got '%s'", rec.Body.String())
		}
	})

	t.Run("error_request_5xx", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error"))
		})

		req := httptest.NewRequest("GET", "/error", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", rec.Code)
		}
	})

	t.Run("with_user_id_header", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("POST", "/user-action", nil)
		req.Header.Set("X-User-ID", "user123")
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})

	t.Run("4xx_status_not_captured", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})

		req := httptest.NewRequest("GET", "/bad-request", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rec.Code)
		}
	})
}

func TestSentryMiddleware_Repanic(t *testing.T) {
	// Test repanic option
	middleware := SentryMiddleware(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler := middleware(handler)
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestSentryRecoveryMiddleware(t *testing.T) {
	middleware := SentryRecoveryMiddleware()

	t.Run("normal_request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		})

		req := httptest.NewRequest("GET", "/normal", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}

		if rec.Body.String() != "Success" {
			t.Errorf("Expected body 'Success', got '%s'", rec.Body.String())
		}
	})

	t.Run("panic_recovery", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		req := httptest.NewRequest("GET", "/panic", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "Internal Server Error") {
			t.Errorf("Expected error message in response, got '%s'", body)
		}
	})

	t.Run("nil_panic_recovery", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(nil)
		})

		req := httptest.NewRequest("GET", "/nil-panic", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", rec.Code)
		}
	})

	t.Run("error_panic_recovery", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(errors.New("test error panic"))
		})

		req := httptest.NewRequest("GET", "/error-panic", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", rec.Code)
		}
	})
}

func TestResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		written:        false,
	}

	t.Run("write_header", func(t *testing.T) {
		rw.WriteHeader(http.StatusCreated)
		
		if rw.statusCode != http.StatusCreated {
			t.Errorf("Expected status code 201, got %d", rw.statusCode)
		}

		if !rw.written {
			t.Error("Expected written flag to be true")
		}

		// Second call should not change status
		rw.WriteHeader(http.StatusBadRequest)
		if rw.statusCode != http.StatusCreated {
			t.Errorf("Status should remain 201, got %d", rw.statusCode)
		}
	})

	t.Run("write_without_header", func(t *testing.T) {
		rw2 := &responseWriter{
			ResponseWriter: httptest.NewRecorder(),
			statusCode:     http.StatusOK,
			written:        false,
		}

		n, err := rw2.Write([]byte("test"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if n != 4 {
			t.Errorf("Expected to write 4 bytes, wrote %d", n)
		}

		if !rw2.written {
			t.Error("Expected written flag to be true after Write")
		}

		if rw2.statusCode != http.StatusOK {
			t.Errorf("Expected status code 200 after Write, got %d", rw2.statusCode)
		}
	})

	t.Run("write_with_header", func(t *testing.T) {
		rw3 := &responseWriter{
			ResponseWriter: httptest.NewRecorder(),
			statusCode:     http.StatusOK,
			written:        false,
		}

		rw3.WriteHeader(http.StatusAccepted)
		n, err := rw3.Write([]byte("test"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		if n != 4 {
			t.Errorf("Expected to write 4 bytes, wrote %d", n)
		}

		if rw3.statusCode != http.StatusAccepted {
			t.Errorf("Expected status code 202, got %d", rw3.statusCode)
		}
	})
}

func TestCaptureError(t *testing.T) {
	// Initialize Sentry for testing
	err := sentry.Init(sentry.ClientOptions{
		Dsn:       "https://test@sentry.example.com/1",
		Transport: &mockTransport{},
	})
	if err != nil {
		t.Fatalf("Failed to init Sentry: %v", err)
	}
	defer sentry.Flush(time.Second)

	ctx := context.Background()

	t.Run("capture_error_with_context", func(t *testing.T) {
		testErr := errors.New("test error")
		tags := map[string]string{
			"component": "test",
			"operation": "test_operation",
		}
		extra := map[string]interface{}{
			"user_id": 123,
			"request_id": "req-123",
		}

		// Should not panic
		CaptureError(ctx, testErr, tags, extra)
	})

	t.Run("capture_nil_error", func(t *testing.T) {
		// Should not panic or do anything
		CaptureError(ctx, nil, nil, nil)
	})

	t.Run("capture_error_no_context", func(t *testing.T) {
		testErr := errors.New("test error without context")
		
		// Should not panic
		CaptureError(context.Background(), testErr, nil, nil)
	})

	t.Run("capture_error_empty_tags_extra", func(t *testing.T) {
		testErr := errors.New("test error")
		
		// Should not panic with empty maps
		CaptureError(ctx, testErr, map[string]string{}, map[string]interface{}{})
	})
}

func TestCaptureMessage(t *testing.T) {
	// Initialize Sentry for testing
	err := sentry.Init(sentry.ClientOptions{
		Dsn:       "https://test@sentry.example.com/1",
		Transport: &mockTransport{},
	})
	if err != nil {
		t.Fatalf("Failed to init Sentry: %v", err)
	}
	defer sentry.Flush(time.Second)

	ctx := context.Background()

	t.Run("capture_message_info", func(t *testing.T) {
		tags := map[string]string{
			"module": "test",
		}
		extra := map[string]interface{}{
			"timestamp": time.Now(),
		}

		// Should not panic
		CaptureMessage(ctx, "Test info message", sentry.LevelInfo, tags, extra)
	})

	t.Run("capture_message_error", func(t *testing.T) {
		// Should not panic
		CaptureMessage(ctx, "Test error message", sentry.LevelError, nil, nil)
	})

	t.Run("capture_message_warning", func(t *testing.T) {
		// Should not panic
		CaptureMessage(ctx, "Test warning message", sentry.LevelWarning, nil, nil)
	})

	t.Run("capture_message_debug", func(t *testing.T) {
		// Should not panic
		CaptureMessage(ctx, "Test debug message", sentry.LevelDebug, nil, nil)
	})
}

func TestAddBreadcrumb(t *testing.T) {
	// Initialize Sentry for testing
	err := sentry.Init(sentry.ClientOptions{
		Dsn:       "https://test@sentry.example.com/1",
		Transport: &mockTransport{},
	})
	if err != nil {
		t.Fatalf("Failed to init Sentry: %v", err)
	}
	defer sentry.Flush(time.Second)

	ctx := context.Background()

	t.Run("add_breadcrumb", func(t *testing.T) {
		breadcrumb := &sentry.Breadcrumb{
			Type:      "http",
			Category:  "request",
			Message:   "HTTP GET /api/test",
			Level:     sentry.LevelInfo,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"method": "GET",
				"url":    "/api/test",
			},
		}

		// Should not panic
		AddBreadcrumb(ctx, breadcrumb)
	})

	t.Run("add_breadcrumb_minimal", func(t *testing.T) {
		breadcrumb := &sentry.Breadcrumb{
			Message: "Simple breadcrumb",
		}

		// Should not panic
		AddBreadcrumb(ctx, breadcrumb)
	})

	t.Run("add_breadcrumb_with_data", func(t *testing.T) {
		breadcrumb := &sentry.Breadcrumb{
			Type:     "navigation",
			Category: "ui",
			Message:  "User clicked button",
			Level:    sentry.LevelInfo,
			Data: map[string]interface{}{
				"button_id": "submit-btn",
				"page":      "/dashboard",
			},
		}

		// Should not panic
		AddBreadcrumb(ctx, breadcrumb)
	})
}

func TestSentryWithContext(t *testing.T) {
	// Test that Sentry context handling works correctly
	err := sentry.Init(sentry.ClientOptions{
		Dsn:       "https://test@sentry.example.com/1",
		Transport: &mockTransport{},
	})
	if err != nil {
		t.Fatalf("Failed to init Sentry: %v", err)
	}
	defer sentry.Flush(time.Second)

	t.Run("middleware_with_sentry_context", func(t *testing.T) {
		middleware := SentryMiddleware(false)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Test that Sentry hub is available in context
			hub := sentry.GetHubFromContext(r.Context())
			if hub != nil {
				hub.Scope().SetTag("handler", "test")
			}
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/context-test", nil)
		rec := httptest.NewRecorder()

		wrappedHandler := middleware(handler)
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})
}

// mockTransport is a mock Sentry transport for testing
type mockTransport struct{}

func (t *mockTransport) Flush(_ time.Duration) bool {
	return true
}

func (t *mockTransport) Configure(_ sentry.ClientOptions) {}

func (t *mockTransport) SendEvent(_ *sentry.Event) {}

func (t *mockTransport) Close() {}

func (t *mockTransport) FlushWithContext(_ context.Context) bool {
	return true
}

func BenchmarkSentryMiddleware(b *testing.B) {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:       "https://test@sentry.example.com/1",
		Transport: &mockTransport{},
	})
	if err != nil {
		b.Fatalf("Failed to init Sentry: %v", err)
	}
	defer sentry.Flush(time.Second)

	middleware := SentryMiddleware(false)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/benchmark", nil)
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)
	}
}

func BenchmarkSentryRecoveryMiddleware(b *testing.B) {
	middleware := SentryRecoveryMiddleware()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrappedHandler := middleware(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/benchmark", nil)
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)
	}
}

func BenchmarkResponseWriter(b *testing.B) {
	rec := httptest.NewRecorder()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw := &responseWriter{
			ResponseWriter: rec,
			statusCode:     http.StatusOK,
			written:        false,
		}
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("test"))
	}
}