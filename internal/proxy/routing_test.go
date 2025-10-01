package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestRouting_Auth0PathsNotCapturedByS3Routes(t *testing.T) {
	// Create minimal config with Auth0 enabled
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: "/tmp",
			},
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		Auth0: config.Auth0Config{
			Enabled:      true,
			Domain:       "test.auth0.com",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			SessionKey:   "test-session-key-32-characters!",
		},
		UI: config.UIConfig{
			Enabled: true,
		},
	}

	server, err := NewServer(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test that Auth0 login route is handled by Auth0 handler, not S3 handler
	req := httptest.NewRequest("GET", "/api/auth/login", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Should be handled by Auth0 handler (redirect to Auth0)
	// Not by S3 handler (which would return bucket not found error)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "test.auth0.com")
	assert.NotContains(t, w.Body.String(), "no backend found for bucket")
}

func TestRouting_S3BucketsStillWork(t *testing.T) {
	// Create minimal config
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: "/tmp",
			},
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		Auth0: config.Auth0Config{
			Enabled: false, // Disable Auth0 for this test
		},
		UI: config.UIConfig{
			Enabled: true,
		},
	}

	server, err := NewServer(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test that normal S3 bucket requests still work
	req := httptest.NewRequest("GET", "/mybucket", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Should be handled by S3 handler (expect some S3-related error, not routing error)
	// The exact error depends on backend configuration, but it shouldn't be a routing issue
	assert.NotEqual(t, http.StatusNotFound, w.Code) // Route should be found
}

func TestRouting_ApiPathsExcludedFromS3(t *testing.T) {
	// Test that bucket named "api" is correctly excluded from S3 routing
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: "/tmp",
			},
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		Auth0: config.Auth0Config{
			Enabled: false,
		},
		UI: config.UIConfig{
			Enabled: true,
		},
	}

	server, err := NewServer(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Request to /api should not be treated as S3 bucket
	req := httptest.NewRequest("GET", "/api", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Should return 404 (no route matches) rather than being treated as S3 bucket
	assert.Equal(t, http.StatusNotFound, w.Code)
}