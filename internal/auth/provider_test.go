package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.AuthConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "none auth type",
			cfg: config.AuthConfig{
				Type: "none",
			},
			wantErr: false,
		},
		{
			name: "basic auth type",
			cfg: config.AuthConfig{
				Type:       "basic",
				Identity:   "user",
				Credential: "pass",
			},
			wantErr: false,
		},
		{
			name: "basic auth missing identity",
			cfg: config.AuthConfig{
				Type:       "basic",
				Identity:   "",
				Credential: "pass",
			},
			wantErr:     true,
			errContains: "basic auth requires identity and credential",
		},
		{
			name: "basic auth missing credential",
			cfg: config.AuthConfig{
				Type:       "basic",
				Identity:   "user",
				Credential: "",
			},
			wantErr:     true,
			errContains: "basic auth requires identity and credential",
		},
		{
			name: "awsv2 auth type",
			cfg: config.AuthConfig{
				Type:       "awsv2",
				Identity:   "TESTKEY12345",
				Credential: "fakeSecretForTesting",
			},
			wantErr: false,
		},
		{
			name: "awsv2 auth missing identity",
			cfg: config.AuthConfig{
				Type:       "awsv2",
				Identity:   "",
				Credential: "secret",
			},
			wantErr:     true,
			errContains: "awsv2 auth requires identity and credential",
		},
		{
			name: "awsv4 auth type",
			cfg: config.AuthConfig{
				Type:       "awsv4",
				Identity:   "TESTKEY12345",
				Credential: "fakeSecretForTesting",
			},
			wantErr: false,
		},
		{
			name: "invalid auth type",
			cfg: config.AuthConfig{
				Type:       "invalid",
				Identity:   "user",
				Credential: "pass",
			},
			wantErr:     true,
			errContains: "unsupported auth type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewProvider() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("NewProvider() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("NewProvider() unexpected error = %v", err)
				}
				if provider == nil {
					t.Errorf("NewProvider() returned nil provider")
				}
			}
		})
	}
}

func TestNoneProvider(t *testing.T) {
	provider := &NoneProvider{}

	req := httptest.NewRequest("GET", "/test", nil)
	err := provider.Authenticate(req)

	if err != nil {
		t.Errorf("Authenticate() error = %v, want nil", err)
	}
}

func TestBasicProvider(t *testing.T) {
	provider := &BasicProvider{
		identity:   "testuser",
		credential: "testpass",
	}

	tests := []struct {
		name        string
		authHeader  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid credentials",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			wantErr:    false,
		},
		{
			name:        "missing auth header",
			authHeader:  "",
			wantErr:     true,
			errContains: "missing basic auth credentials",
		},
		{
			name:        "invalid base64",
			authHeader:  "Basic invalid!@#$",
			wantErr:     true,
			errContains: "missing basic auth credentials",
		},
		{
			name:        "wrong username",
			authHeader:  "Basic " + base64.StdEncoding.EncodeToString([]byte("wronguser:testpass")),
			wantErr:     true,
			errContains: "invalid credentials",
		},
		{
			name:        "wrong password",
			authHeader:  "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:wrongpass")),
			wantErr:     true,
			errContains: "invalid credentials",
		},
		{
			name:        "missing colon",
			authHeader:  "Basic " + base64.StdEncoding.EncodeToString([]byte("testusernopass")),
			wantErr:     true,
			errContains: "missing basic auth credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			err := provider.Authenticate(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Authenticate() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Authenticate() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Authenticate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestAWSV2Provider(t *testing.T) {
	provider := &AWSV2Provider{
		identity:   "TESTKEY67890EXAMPLE",
		credential: "fakeTestSecretKey456NotRealCredentials789",
	}

	tests := []struct {
		name        string
		setupReq    func(*http.Request)
		wantErr     bool
		errContains string
	}{
		{
			name: "valid v2 signature",
			setupReq: func(req *http.Request) {
				// This is a simplified test - in reality, AWS v2 signatures are complex
				req.Header.Set("Authorization", "AWS TESTKEY67890EXAMPLE:signature")
				req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
			},
			wantErr: true, // Will fail signature verification
		},
		{
			name: "missing authorization header",
			setupReq: func(req *http.Request) {
				// No auth header
			},
			wantErr:     true,
			errContains: "missing authorization header",
		},
		{
			name: "wrong auth type",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")
			},
			wantErr:     true,
			errContains: "invalid authorization header format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/bucket/key", nil)
			if tt.setupReq != nil {
				tt.setupReq(req)
			}

			err := provider.Authenticate(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Authenticate() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Authenticate() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Authenticate() unexpected error = %v", err)
				}
			}
		})
	}
}

// generateAWSV4Signature generates a proper AWS V4 signature for testing
func generateAWSV4Signature(method, uri, query, host, amzDate, contentHash, accessKey, secretKey, signedHeaders string) string {
	// Extract date from amzDate
	dateStr := amzDate[:8] // YYYYMMDD
	region := "us-east-1"
	service := "s3"
	
	// Build canonical request
	canonicalURI := uri
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	
	canonicalQueryString := query
	
	// Build canonical headers for the signed headers
	canonicalHeaders := ""
	headersList := strings.Split(signedHeaders, ";")
	for _, header := range headersList {
		switch header {
		case "host":
			canonicalHeaders += fmt.Sprintf("host:%s\n", host)
		case "x-amz-date":
			canonicalHeaders += fmt.Sprintf("x-amz-date:%s\n", amzDate)
		case "x-amz-content-sha256":
			canonicalHeaders += fmt.Sprintf("x-amz-content-sha256:%s\n", contentHash)
		}
	}
	
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, contentHash)
	
	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStr, region, service)
	hashedCanonicalRequest := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonicalRequestHex := hex.EncodeToString(hashedCanonicalRequest[:])
	
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm, amzDate, credentialScope, hashedCanonicalRequestHex)
	
	// Calculate signing key (same as in the main code)
	kDate := hmacSha256([]byte("AWS4"+secretKey), dateStr)
	kRegion := hmacSha256(kDate, region)
	kService := hmacSha256(kRegion, service)
	kSigning := hmacSha256(kService, "aws4_request")
	
	// Calculate signature
	signature := hmacSha256(kSigning, stringToSign)
	return hex.EncodeToString(signature)
}

// hmacSha256 helper function
func hmacSha256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func TestAWSV4Provider(t *testing.T) {
	// These are fake test credentials, not real AWS keys
	provider := &AWSV4Provider{
		identity:   "AKIATEST12345EXAMPLE",
		credential: "testSecretKey123NotRealCredentials456",
	}

	tests := []struct {
		name        string
		setupReq    func(*http.Request)
		wantErr     bool
		errContains string
	}{
		{
			name: "valid v4 signature",
			setupReq: func(req *http.Request) {
				// Generate proper AWS v4 signature for the test request
				amzDate := "20230101T000000Z"
				contentHash := "UNSIGNED-PAYLOAD"
				signedHeaders := "host;x-amz-date"
				
				// Set required headers
				req.Header.Set("X-Amz-Date", amzDate)
				req.Header.Set("X-Amz-Content-Sha256", contentHash)
				
				// Generate the proper signature
				signature := generateAWSV4Signature(
					req.Method,           // GET
					req.URL.Path,         // /bucket/key
					"",                   // no query string
					req.Host,             // host from request
					amzDate,              // timestamp
					contentHash,          // content hash
					"AKIATEST12345EXAMPLE", // fake access key for testing
					"testSecretKey123NotRealCredentials456", // fake secret key for testing
					signedHeaders,        // signed headers
				)
				
				// Set authorization header with proper signature
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential=AKIATEST12345EXAMPLE/20230101/us-east-1/s3/aws4_request, "+
						"SignedHeaders="+signedHeaders+", Signature="+signature)
			},
			wantErr: false,
		},
		{
			name: "missing authorization header",
			setupReq: func(req *http.Request) {
				// No auth header
			},
			wantErr:     true,
			errContains: "missing authorization header",
		},
		{
			name: "wrong auth type",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")
			},
			wantErr:     true,
			errContains: "invalid authorization header format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/bucket/key", nil)
			if tt.setupReq != nil {
				tt.setupReq(req)
			}

			err := provider.Authenticate(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Authenticate() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Authenticate() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Authenticate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestFastAWSProvider(t *testing.T) {
	provider := &FastAWSProvider{
		accessKey: "TESTKEY67890EXAMPLE",
		secretKey: "fakeTestSecretKeyForValidation123456", // fake test secret, not real
		cache:     make(map[string]cacheEntry),
	}

	tests := []struct {
		name        string
		setupReq    func(*http.Request)
		wantErr     bool
		errContains string
	}{
		{
			name: "valid v4 signature",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=TESTKEY67890EXAMPLE/20230101/us-east-1/s3/aws4_request")
				req.Header.Set("X-Amz-Date", "20230101T000000Z")
			},
			wantErr: false, // Fast path validation
		},
		{
			name: "valid v2 signature",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "AWS TESTKEY67890EXAMPLE:signature")
			},
			wantErr: false, // Fast path validation
		},
		{
			name: "missing authorization",
			setupReq: func(req *http.Request) {
				// No auth header
			},
			wantErr:     true,
			errContains: "missing authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/bucket/key", nil)
			if tt.setupReq != nil {
				tt.setupReq(req)
			}

			err := provider.Authenticate(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Authenticate() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Authenticate() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Authenticate() unexpected error = %v", err)
				}
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}
