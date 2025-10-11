package proxy

import (
	"crypto/tls"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestAuth0Handler_validateCallbackState(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name        string
		setupState  string
		queryState  string
		expectError bool
		description string
	}{
		{
			name:        "valid_state_match",
			setupState:  "valid-csrf-state-12345",
			queryState:  "valid-csrf-state-12345",
			expectError: false,
			description: "Valid matching state should pass",
		},
		{
			name:        "invalid_state_mismatch",
			setupState:  "valid-csrf-state-12345",
			queryState:  "different-state-67890",
			expectError: true,
			description: "Mismatched state should fail",
		},
		{
			name:        "empty_query_state",
			setupState:  "valid-csrf-state-12345",
			queryState:  "",
			expectError: true,
			description: "Empty query state should fail",
		},
		{
			name:        "no_session_state",
			setupState:  "",
			queryState:  "some-state",
			expectError: true,
			description: "No session state should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with query state
			req := httptest.NewRequest("GET", "/auth/callback?state="+url.QueryEscape(tt.queryState), nil)
			w := httptest.NewRecorder()

			// Set up session state if provided
			if tt.setupState != "" {
				session, _ := handler.store.Get(req, sessionName)
				session.Values["state"] = tt.setupState
				session.Save(req, w)
			}

			// Test validation
			session, err := handler.validateCallbackState(req)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, session)
			}
		})
	}
}

func TestAuth0Handler_computeSessionIntegrityHash(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	userSub := "auth0|123456789"
	expiry := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	// Test hash generation
	hash1 := handler.computeSessionIntegrityHash(userSub, expiry)
	hash2 := handler.computeSessionIntegrityHash(userSub, expiry)

	// Same inputs should produce same hash
	assert.Equal(t, hash1, hash2, "Same inputs should produce same hash")
	assert.NotEmpty(t, hash1, "Hash should not be empty")
	assert.Len(t, hash1, 64, "SHA256 hash should be 64 characters")

	// Different inputs should produce different hashes
	differentExpiry := expiry.Add(1 * time.Hour)
	hash3 := handler.computeSessionIntegrityHash(userSub, differentExpiry)
	assert.NotEqual(t, hash1, hash3, "Different expiry should produce different hash")

	differentUser := "auth0|987654321"
	hash4 := handler.computeSessionIntegrityHash(differentUser, expiry)
	assert.NotEqual(t, hash1, hash4, "Different user should produce different hash")
}

func TestAuth0Handler_safeStringValue(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "string_input",
			input:    "test-string",
			expected: "test-string",
		},
		{
			name:     "int_input",
			input:    42,
			expected: "42",
		},
		{
			name:     "nil_input",
			input:    nil,
			expected: "",
		},
		{
			name:     "bool_true",
			input:    true,
			expected: "true",
		},
		{
			name:     "bool_false",
			input:    false,
			expected: "false",
		},
		{
			name:     "float_input",
			input:    3.14,
			expected: "3.14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.safeStringValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuth0Handler_convertToCommaSeparated(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "string_slice",
			input:    []string{"admin", "user", "guest"},
			expected: "admin,user,guest",
		},
		{
			name:     "interface_slice",
			input:    []interface{}{"role1", "role2", 123},
			expected: "role1,role2,123",
		},
		{
			name:     "single_string",
			input:    "single-role",
			expected: "single-role",
		},
		{
			name:     "nil_input",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty_string_slice",
			input:    []string{},
			expected: "",
		},
		{
			name:     "empty_interface_slice",
			input:    []interface{}{},
			expected: "",
		},
		{
			name:     "number_input",
			input:    42,
			expected: "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.convertToCommaSeparated(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuth0Handler_shouldUseSecureCookies(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name        string
		tlsEnabled  string
		behindProxy string
		xForwarded  string
		hasTLS      bool
		expected    bool
		description string
	}{
		{
			name:        "tls_enabled_env",
			tlsEnabled:  "true",
			behindProxy: "",
			xForwarded:  "",
			hasTLS:      false,
			expected:    true,
			description: "TLS_ENABLED=true should use secure cookies",
		},
		{
			name:        "behind_proxy_env",
			tlsEnabled:  "",
			behindProxy: "true",
			xForwarded:  "",
			hasTLS:      false,
			expected:    true,
			description: "BEHIND_PROXY=true should use secure cookies",
		},
		{
			name:        "x_forwarded_proto_https",
			tlsEnabled:  "",
			behindProxy: "",
			xForwarded:  "https",
			hasTLS:      false,
			expected:    true,
			description: "X-Forwarded-Proto: https should use secure cookies",
		},
		{
			name:        "direct_tls_connection",
			tlsEnabled:  "",
			behindProxy: "",
			xForwarded:  "",
			hasTLS:      true,
			expected:    false, // Note: this function doesn't check r.TLS directly
			description: "Direct TLS connection alone should not trigger secure cookies in this function",
		},
		{
			name:        "no_secure_indicators",
			tlsEnabled:  "",
			behindProxy: "",
			xForwarded:  "",
			hasTLS:      false,
			expected:    false,
			description: "No secure indicators should not use secure cookies",
		},
		{
			name:        "x_forwarded_proto_http",
			tlsEnabled:  "",
			behindProxy: "",
			xForwarded:  "http",
			hasTLS:      false,
			expected:    false,
			description: "X-Forwarded-Proto: http should not use secure cookies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			if tt.tlsEnabled != "" {
				t.Setenv("TLS_ENABLED", tt.tlsEnabled)
			}
			if tt.behindProxy != "" {
				t.Setenv("BEHIND_PROXY", tt.behindProxy)
			}

			// Create request with headers
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.xForwarded != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xForwarded)
			}

			result := handler.shouldUseSecureCookies(req)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestGetRedirectURI(t *testing.T) {
	tests := []struct {
		name           string
		configURI      string
		requestHost    string
		requestTLS     bool
		xForwardedHost string
		xForwardedProto string
		expected       string
		description    string
	}{
		{
			name:        "config_uri_provided",
			configURI:   "https://custom.example.com/callback",
			requestHost: "localhost:8080",
			expected:    "https://custom.example.com/callback",
			description: "Should use config URI when provided",
		},
		{
			name:        "http_request",
			configURI:   "",
			requestHost: "localhost:8080",
			requestTLS:  false,
			expected:    "http://localhost:8080/auth/callback",
			description: "Should construct HTTP URI for non-TLS request",
		},
		{
			name:        "https_request_with_tls",
			configURI:   "",
			requestHost: "example.com",
			requestTLS:  true,
			expected:    "https://example.com/auth/callback",
			description: "Should construct HTTPS URI for TLS request",
		},
		{
			name:            "x_forwarded_proto_https",
			configURI:       "",
			requestHost:     "localhost:8080",
			requestTLS:      false,
			xForwardedProto: "https",
			expected:        "https://localhost:8080/auth/callback",
			description:     "Should use HTTPS when X-Forwarded-Proto is https",
		},
		{
			name:           "x_forwarded_host",
			configURI:      "",
			requestHost:    "localhost:8080",
			requestTLS:     false,
			xForwardedHost: "proxy.example.com",
			expected:       "http://proxy.example.com/auth/callback",
			description:    "Should use X-Forwarded-Host when provided",
		},
		{
			name:            "both_forwarded_headers",
			configURI:       "",
			requestHost:     "localhost:8080",
			requestTLS:      false,
			xForwardedHost:  "proxy.example.com",
			xForwardedProto: "https",
			expected:        "https://proxy.example.com/auth/callback",
			description:     "Should use both forwarded headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.requestHost+"/test", nil)
			
			if tt.requestTLS {
				req.TLS = &tls.ConnectionState{} // Non-nil to indicate TLS
			}
			
			if tt.xForwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.xForwardedHost)
			}
			
			if tt.xForwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xForwardedProto)
			}

			result := getRedirectURI(req, tt.configURI)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestGetReturnToURI(t *testing.T) {
	tests := []struct {
		name           string
		configURI      string
		requestHost    string
		requestTLS     bool
		xForwardedHost string
		xForwardedProto string
		expected       string
		description    string
	}{
		{
			name:        "config_uri_provided",
			configURI:   "https://custom.example.com/home",
			requestHost: "localhost:8080",
			expected:    "https://custom.example.com/home",
			description: "Should use config URI when provided",
		},
		{
			name:        "http_request",
			configURI:   "",
			requestHost: "localhost:8080",
			requestTLS:  false,
			expected:    "http://localhost:8080/ui/",
			description: "Should construct HTTP URI for non-TLS request",
		},
		{
			name:        "https_request_with_tls",
			configURI:   "",
			requestHost: "example.com",
			requestTLS:  true,
			expected:    "https://example.com/ui/",
			description: "Should construct HTTPS URI for TLS request",
		},
		{
			name:            "x_forwarded_proto_https",
			configURI:       "",
			requestHost:     "localhost:8080",
			requestTLS:      false,
			xForwardedProto: "https",
			expected:        "https://localhost:8080/ui/",
			description:     "Should use HTTPS when X-Forwarded-Proto is https",
		},
		{
			name:           "x_forwarded_host",
			configURI:      "",
			requestHost:    "localhost:8080",
			requestTLS:     false,
			xForwardedHost: "proxy.example.com",
			expected:       "http://proxy.example.com/ui/",
			description:    "Should use X-Forwarded-Host when provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.requestHost+"/test", nil)
			
			if tt.requestTLS {
				req.TLS = &tls.ConnectionState{} // Non-nil to indicate TLS
			}
			
			if tt.xForwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.xForwardedHost)
			}
			
			if tt.xForwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xForwardedProto)
			}

			result := getReturnToURI(req, tt.configURI)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}