package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

func TestGracefulShutdown(t *testing.T) {
	// Create a minimal config for testing
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: "/tmp/test-storage",
			},
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		S3: config.S3Config{
			Region: "us-east-1",
		},
	}

	// Create server
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	t.Run("HealthCheckWhenActive", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		server.healthCheck(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if w.Header().Get("X-Shutdown-Status") != "active" {
			t.Errorf("Expected X-Shutdown-Status: active, got %s", w.Header().Get("X-Shutdown-Status"))
		}
	})

	t.Run("HealthCheckWhenShuttingDown", func(t *testing.T) {
		// Mark server as shutting down
		server.SetShuttingDown()

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		server.healthCheck(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status 503, got %d", w.Code)
		}

		if w.Header().Get("X-Shutdown-Status") != "in-progress" {
			t.Errorf("Expected X-Shutdown-Status: in-progress, got %s", w.Header().Get("X-Shutdown-Status"))
		}
	})

	t.Run("ReadinessCheckWhenActive", func(t *testing.T) {
		// Reset shutdown state
		server.shuttingDown = 0

		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		server.readinessCheck(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("ReadinessCheckWhenShuttingDown", func(t *testing.T) {
		// Mark server as shutting down
		server.SetShuttingDown()

		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		server.readinessCheck(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status 503, got %d", w.Code)
		}
	})

	t.Run("ShutdownStateManagement", func(t *testing.T) {
		// Reset shutdown state
		server.shuttingDown = 0

		if server.IsShuttingDown() {
			t.Error("Server should not be shutting down initially")
		}

		server.SetShuttingDown()

		if !server.IsShuttingDown() {
			t.Error("Server should be shutting down after SetShuttingDown()")
		}
	})

	// Test resource cleanup
	t.Run("ResourceCleanup", func(t *testing.T) {
		err := server.Close()
		if err != nil {
			t.Errorf("Server.Close() returned error: %v", err)
		}
	})
}

func TestConcurrentShutdown(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: "/tmp/test-storage",
			},
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		S3: config.S3Config{
			Region: "us-east-1",
		},
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test concurrent access during shutdown
	done := make(chan bool, 10)

	// Start multiple goroutines checking health
	for i := 0; i < 5; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()
			server.healthCheck(w, req)
			done <- true
		}()
	}

	// Trigger shutdown
	server.SetShuttingDown()

	// Start more goroutines after shutdown signal
	for i := 0; i < 5; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()
			server.healthCheck(w, req)
			// These should return 503
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("Expected 503 during shutdown, got %d", w.Code)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Good
		case <-time.After(time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	// Clean up
	server.Close()
}