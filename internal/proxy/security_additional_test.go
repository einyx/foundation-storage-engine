package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

// Mock session structure for testing
type mockSession struct {
	values map[interface{}]interface{}
}

func (m *mockSession) Values() map[interface{}]interface{} {
	return m.values
}

func TestValidateSecureSession_Security(t *testing.T) {
	server := &Server{
		config: &config.Config{
			Auth0: config.Auth0Config{
				ClientSecret: "test-secret-key-for-hmac",
			},
		},
	}

	validExpiration := time.Now().Add(1 * time.Hour)
	expiredTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		session  interface{}
		expected bool
		desc     string
	}{
		{
			name: "valid_session_with_integrity",
			session: &mockSession{
				values: map[interface{}]interface{}{
					"authenticated": true,
					"user_sub":      "test-user-123",
					"expires_at":    validExpiration,
					"integrity_hash": server.computeSessionIntegrityHash("test-user-123", validExpiration),
				},
			},
			expected: true,
			desc:     "Valid session with proper expiration and integrity hash should pass",
		},
		{
			name: "expired_session",
			session: &mockSession{
				values: map[interface{}]interface{}{
					"authenticated": true,
					"user_sub":      "test-user-123",
					"expires_at":    expiredTime,
					"integrity_hash": server.computeSessionIntegrityHash("test-user-123", expiredTime),
				},
			},
			expected: false,
			desc:     "Expired session should be rejected",
		},
		{
			name: "session_without_expiration",
			session: &mockSession{
				values: map[interface{}]interface{}{
					"authenticated": true,
					"user_sub":      "test-user-123",
				},
			},
			expected: false,
			desc:     "Session without expiration should be rejected for security",
		},
		{
			name: "session_without_integrity_hash",
			session: &mockSession{
				values: map[interface{}]interface{}{
					"authenticated": true,
					"user_sub":      "test-user-123",
					"expires_at":    validExpiration,
				},
			},
			expected: false,
			desc:     "Session without integrity hash should be rejected",
		},
		{
			name: "session_with_tampered_integrity",
			session: &mockSession{
				values: map[interface{}]interface{}{
					"authenticated": true,
					"user_sub":      "test-user-123",
					"expires_at":    validExpiration,
					"integrity_hash": "tampered-hash-value",
				},
			},
			expected: false,
			desc:     "Session with tampered integrity hash should be rejected",
		},
		{
			name: "unauthenticated_session",
			session: &mockSession{
				values: map[interface{}]interface{}{
					"authenticated":  false,
					"user_sub":       "test-user-123",
					"expires_at":     validExpiration,
					"integrity_hash": server.computeSessionIntegrityHash("test-user-123", validExpiration),
				},
			},
			expected: false,
			desc:     "Unauthenticated session should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.validateSecureSession(tt.session)
			if result != tt.expected {
				t.Errorf("validateSecureSession() = %v, expected %v: %s", result, tt.expected, tt.desc)
			}
		})
	}
}

func TestValidateAPIKeySignature_Security(t *testing.T) {
	// Create a mock API key for testing
	apiKey := &APIKey{
		AccessKey: "fse_test_access_key",
		SecretKey: "test-secret-key-for-validation-123456",
		Name:      "test-key",
		UserID:    "test-user-123",
	}

	server := &Server{}

	tests := []struct {
		name     string
		setupReq func(*http.Request)
		expected bool
		desc     string
	}{
		{
			name: "missing_authorization_header",
			setupReq: func(req *http.Request) {
				// No authorization header
			},
			expected: false,
			desc:     "Request without authorization header should be rejected",
		},
		{
			name: "unsupported_auth_method",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")
			},
			expected: false,
			desc:     "Unsupported authorization method should be rejected",
		},
		{
			name: "malformed_aws_v4_header",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 MalformedHeader")
			},
			expected: false,
			desc:     "Malformed AWS V4 header should be rejected",
		},
		{
			name: "malformed_aws_v2_header",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "AWS malformed")
			},
			expected: false,
			desc:     "Malformed AWS V2 header should be rejected",
		},
		{
			name: "aws_v4_missing_signature",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=fse_test_access_key/20230101/us-east-1/s3/aws4_request, SignedHeaders=host")
			},
			expected: false,
			desc:     "AWS V4 header without signature should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
			if tt.setupReq != nil {
				tt.setupReq(req)
			}

			result := server.validateAPIKeySignature(req, apiKey)
			if result != tt.expected {
				t.Errorf("validateAPIKeySignature() = %v, expected %v: %s", result, tt.expected, tt.desc)
			}
		})
	}
}