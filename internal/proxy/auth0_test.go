package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuth0Handler(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:        true,
		Domain:         "test.auth0.com",
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		SessionTimeout: 24 * time.Hour,
		TokenCacheTTL:  5 * time.Minute,
		JWTValidation:  true,
	}

	handler := NewAuth0Handler(cfg)

	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.NotNil(t, handler.store)
	assert.NotNil(t, handler.jwksCache)
	assert.NotNil(t, handler.tokenCache)
	assert.NotNil(t, handler.metrics)
	assert.NotNil(t, handler.auditLogger)
}

func TestAuth0Handler_RequireUIAuth_Unauthenticated(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:       true,
		Domain:        "test.auth0.com",
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		SessionKey:    "test-session-key-32-characters!",
		JWTValidation: true,
	}

	handler := NewAuth0Handler(cfg)

	// Test redirect for browser request
	req := httptest.NewRequest("GET", "/ui/", nil)
	w := httptest.NewRecorder()

	testHandler := handler.RequireUIAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testHandler(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	location := w.Header().Get("Location")
	assert.Equal(t, "/api/auth/login", location)
}

func TestAuth0Handler_RequireUIAuth_AJAX_Unauthenticated(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:       true,
		Domain:        "test.auth0.com",
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		SessionKey:    "test-session-key-32-characters!",
		JWTValidation: true,
	}

	handler := NewAuth0Handler(cfg)

	// Test JSON response for AJAX request
	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	testHandler := handler.RequireUIAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "Authentication required")
	assert.Contains(t, w.Body.String(), "/api/auth/login")
}

func TestAuth0Handler_RequireUIAuth_Authenticated(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:       true,
		Domain:        "test.auth0.com",
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		SessionKey:    "test-session-key-32-characters!",
		JWTValidation: true,
	}

	handler := NewAuth0Handler(cfg)

	req := httptest.NewRequest("GET", "/ui/", nil)
	w := httptest.NewRecorder()

	// Create authenticated session
	session, _ := handler.store.Get(req, "auth0-session")
	session.Values["authenticated"] = true
	session.Values["user"] = map[string]interface{}{
		"sub":   "auth0|123456",
		"email": "test@example.com",
		"name":  "Test User",
	}
	session.Save(req, w)

	// Reset recorder for actual test
	w = httptest.NewRecorder()

	handlerCalled := false
	testHandler := handler.RequireUIAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	testHandler(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuth0Handler_CheckS3Permission(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:       true,
		JWTValidation: true,
	}

	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name       string
		user       *UserClaims
		bucket     string
		operation  string
		expected   bool
	}{
		{
			name:      "nil user",
			user:      nil,
			operation: "GetObject",
			expected:  false,
		},
		{
			name: "admin user",
			user: &UserClaims{
				Sub:   "auth0|admin",
				Roles: []string{"admin"},
			},
			operation: "GetObject",
			expected:  true,
		},
		{
			name: "s3 admin user",
			user: &UserClaims{
				Sub:   "auth0|s3admin",
				Roles: []string{"s3:admin"},
			},
			operation: "DeleteBucket",
			expected:  true,
		},
		{
			name: "user with specific permission",
			user: &UserClaims{
				Sub:         "auth0|user",
				Permissions: []string{"s3:GetObject"},
			},
			operation: "GetObject",
			expected:  true,
		},
		{
			name: "user with wildcard permission",
			user: &UserClaims{
				Sub:         "auth0|poweruser",
				Permissions: []string{"s3:*"},
			},
			operation: "PutObject",
			expected:  true,
		},
		{
			name: "user without permission",
			user: &UserClaims{
				Sub:         "auth0|readonly",
				Permissions: []string{"s3:GetObject"},
			},
			operation: "PutObject",
			expected:  false,
		},
		{
			name:      "unknown operation",
			user:      &UserClaims{Sub: "auth0|user"},
			operation: "UnknownOperation",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.CheckS3Permission(tt.user, tt.bucket, "", tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuth0Handler_ValidateJWT_Disabled(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:       true,
		JWTValidation: false,
	}

	handler := NewAuth0Handler(cfg)

	_, err := handler.ValidateJWT("dummy-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT validation is disabled")
}

func TestAuth0Handler_LoginHandler(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:      true,
		Domain:       "test.auth0.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "/api/auth/callback",
		SessionKey:   "test-session-key-32-characters!",
	}

	handler := NewAuth0Handler(cfg)

	req := httptest.NewRequest("GET", "/api/auth/login", nil)
	w := httptest.NewRecorder()

	handler.LoginHandler(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://test.auth0.com/authorize")
	assert.Contains(t, location, "client_id=test-client-id")
	assert.Contains(t, location, "response_type=code")
	assert.Contains(t, location, "scope=openid")
	assert.Contains(t, location, "state=")
}

func TestAuth0Handler_UserInfoHandler_Unauthenticated(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}

	handler := NewAuth0Handler(cfg)

	req := httptest.NewRequest("GET", "/api/auth/userinfo", nil)
	w := httptest.NewRecorder()

	handler.UserInfoHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth0Handler_UserInfoHandler_Authenticated(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}

	handler := NewAuth0Handler(cfg)

	req := httptest.NewRequest("GET", "/api/auth/userinfo", nil)
	w := httptest.NewRecorder()

	// Create authenticated session
	session, _ := handler.store.Get(req, "auth0-session")
	session.Values["authenticated"] = true
	session.Values["user"] = map[string]interface{}{
		"sub":   "auth0|123456",
		"email": "test@example.com",
		"name":  "Test User",
	}
	session.Save(req, w)

	// Reset recorder for actual test
	w = httptest.NewRecorder()

	handler.UserInfoHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "auth0|123456")
	assert.Contains(t, w.Body.String(), "test@example.com")
}

func TestSecurityAuditLogger(t *testing.T) {
	logger := NewSecurityAuditLogger()
	assert.NotNil(t, logger)

	// Test logging functions don't panic
	require.NotPanics(t, func() {
		logger.LogAuthEvent("test_event", "user123", map[string]interface{}{
			"ip": "127.0.0.1",
		})
	})

	require.NotPanics(t, func() {
		logger.LogAccessDenied("user123", "bucket/object", "read", "insufficient permissions")
	})

	require.NotPanics(t, func() {
		logger.LogSecurityEvent("suspicious_activity", map[string]interface{}{
			"ip": "192.168.1.1",
		})
	})
}

func TestAuth0Metrics(t *testing.T) {
	metrics := NewAuth0Metrics()
	assert.NotNil(t, metrics)

	// Test that metric recording doesn't panic
	require.NotPanics(t, func() {
		metrics.RecordLoginAttempt()
		metrics.RecordLoginSuccess()
		metrics.RecordLoginFailure()
		metrics.RecordJWTValidation()
		metrics.RecordJWTCacheHit()
		metrics.RecordJWTCacheMiss()
		metrics.RecordSessionDuration(time.Hour)
		metrics.RecordAuth0APICall(100 * time.Millisecond)
	})
}