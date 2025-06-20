package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/einyx/s3proxy-go/internal/config"
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
				Identity:   "AKIAEXAMPLEKEY",
				Credential: "exampleSecretKey",
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
				Identity:   "AKIAEXAMPLEKEY",
				Credential: "exampleSecretKey",
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
		identity:   "AKIAIOSFODNN7EXAMPLE",
		credential: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
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
				req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:signature")
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

func TestAWSV4Provider(t *testing.T) {
	provider := &AWSV4Provider{
		identity:   "AKIAIOSFODNN7EXAMPLE",
		credential: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
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
				// AWS v4 signature format
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, "+
						"SignedHeaders=host;x-amz-date, Signature=abcd")
				req.Header.Set("X-Amz-Date", "20230101T000000Z")
			},
			wantErr: false, // Simplified validation in test implementation
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
		accessKey: "AKIAIOSFODNN7EXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // pragma: allowlist secret
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
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request")
				req.Header.Set("X-Amz-Date", "20230101T000000Z")
			},
			wantErr: false, // Fast path validation
		},
		{
			name: "valid v2 signature",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:signature")
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
