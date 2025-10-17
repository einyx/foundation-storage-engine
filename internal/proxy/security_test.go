package proxy

import (
	"testing"
	
	"github.com/einyx/foundation-storage-engine/internal/config"
)

func TestIsPublicPath_SecurityValidation(t *testing.T) {
	cfg := &config.Config{}
	server := &Server{
		config: cfg,
	}
	
	// Initialize the authentication manager for testing
	server.authManager = NewAuthenticationManager(cfg, nil, nil)
	
	tests := []struct {
		name     string
		path     string
		expected bool
		desc     string
	}{
		// Valid public paths
		{name: "health_endpoint", path: "/health", expected: true, desc: "Health endpoint should be public"},
		{name: "metrics_endpoint", path: "/metrics", expected: true, desc: "Metrics endpoint should be public"},
		{name: "docs_normal", path: "/docs/api.html", expected: true, desc: "Normal docs path should be public"},
		{name: "auth_endpoint", path: "/api/auth/login", expected: true, desc: "Auth endpoint should be public"},
		
		// Security: reject all paths with traversal attempts (new secure implementation)
		{name: "double_slash_docs", path: "//docs/secret", expected: false, desc: "Double slash should be rejected for security"},
		{name: "dot_slash_docs", path: "/./docs/admin", expected: false, desc: "Dot slash should be rejected for security"},
		{name: "auth_traversal", path: "/api/auth/../admin", expected: false, desc: "Path traversal in auth should be blocked"},
		{name: "docs_traversal", path: "/docs/../admin/secrets", expected: false, desc: "Path traversal in docs should be blocked"},
		{name: "encoded_traversal", path: "/api/auth%2f..%2fadmin", expected: false, desc: "URL encoded traversal should be blocked"},
		
		// Edge cases
		{name: "empty_path", path: "", expected: false, desc: "Empty path should be blocked"},
		{name: "root_path", path: "/", expected: false, desc: "Root path should be private"},
		{name: "relative_path", path: "docs/file", expected: false, desc: "Relative path should be blocked"},
		{name: "backslash_attack", path: "/docs\\..\\admin", expected: false, desc: "Backslash traversal should be blocked"},
		
		// Non-public paths
		{name: "admin_endpoint", path: "/admin/users", expected: false, desc: "Admin endpoint should be private"},
		{name: "api_data", path: "/api/data/users", expected: false, desc: "Non-auth API should be private"},
		{name: "bucket_path", path: "/my-bucket/file.txt", expected: false, desc: "S3 bucket path should be private"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.authManager.isPublicPath(tt.path)
			if result != tt.expected {
				t.Errorf("isPublicPath(%q) = %v, expected %v: %s", tt.path, result, tt.expected, tt.desc)
			}
		})
	}
}

func TestExtractAccessKeyFromV4Auth_Security(t *testing.T) {
	cfg := &config.Config{}
	server := &Server{
		config: cfg,
	}
	
	// Initialize the authentication manager for testing
	server.authManager = NewAuthenticationManager(cfg, nil, nil)
	
	tests := []struct {
		name      string
		authHeader string
		expected  string
		desc      string
	}{
		// Valid cases
		{name: "valid_aws_header", authHeader: "AWS4-HMAC-SHA256 Credential=AKIATEST123/20230101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc", expected: "AKIATEST123", desc: "Valid AWS header should extract key"},
		
		// Security test cases
		{name: "empty_header", authHeader: "", expected: "", desc: "Empty header should return empty"},
		{name: "malformed_no_credential", authHeader: "AWS4-HMAC-SHA256 BadFormat", expected: "", desc: "Missing Credential should return empty"},
		{name: "credential_at_end", authHeader: "AWS4-HMAC-SHA256 Credential=", expected: "", desc: "Credential at end should return empty"},
		{name: "no_delimiter", authHeader: "AWS4-HMAC-SHA256 Credential=AKIATEST123NODELIMITER", expected: "", desc: "No delimiter should return empty"},
		{name: "very_long_key", authHeader: "AWS4-HMAC-SHA256 Credential=" + string(make([]byte, 200)) + "/date", expected: "", desc: "Overly long key should be rejected"},
		{name: "very_short_key", authHeader: "AWS4-HMAC-SHA256 Credential=AB/date", expected: "", desc: "Very short key should be rejected"},
		{name: "comma_delimiter", authHeader: "AWS4-HMAC-SHA256 Credential=AKIATEST123, SignedHeaders=host", expected: "AKIATEST123", desc: "Comma delimiter should work"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.authManager.extractAccessKeyFromV4Auth(tt.authHeader)
			if result != tt.expected {
				t.Errorf("extractAccessKeyFromV4Auth(%q) = %q, expected %q: %s", tt.authHeader, result, tt.expected, tt.desc)
			}
		})
	}
}