package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mock auth provider for testing
type mockAuthProvider struct {
	shouldFail bool
}

func (m *mockAuthProvider) Authenticate(r *http.Request) error {
	if m.shouldFail {
		return &AuthError{Message: "mock authentication failed"}
	}
	return nil
}

func (m *mockAuthProvider) GetSecretKey(accessKey string) (string, error) {
	return "mock-secret", nil
}

// Custom error type for testing
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

func TestAuthenticationMiddleware(t *testing.T) {
	tests := []struct {
		name               string
		authenticated      bool
		shouldAuth         bool
		authProviderFails  bool
		expectedStatus     int
	}{
		{
			name:          "already authenticated via proxy",
			authenticated: true,
			shouldAuth:    false,
			expectedStatus: http.StatusOK,
		},
		{
			name:          "not authenticated, auth succeeds",
			authenticated: false,
			shouldAuth:    true,
			authProviderFails: false,
			expectedStatus: http.StatusOK,
		},
		{
			name:          "not authenticated, auth fails",
			authenticated: false,
			shouldAuth:    true,
			authProviderFails: true,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Create mock auth provider
			authProvider := &mockAuthProvider{shouldFail: tt.authProviderFails}

			// Create middleware
			middleware := AuthenticationMiddleware(authProvider)
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			
			// Set authentication context if specified
			if tt.authenticated {
				ctx := context.WithValue(req.Context(), "authenticated", true)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			wrappedHandler.ServeHTTP(w, req)

			// Check status
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestAdminAuthMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		isAdmin        bool
		expectedStatus int
	}{
		{
			name:           "admin user",
			isAdmin:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "non-admin user",
			isAdmin:        false,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Create middleware
			middleware := AdminAuthMiddleware()
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			
			// Set admin context if specified
			if tt.isAdmin {
				ctx := context.WithValue(req.Context(), "is_admin", true)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			wrappedHandler.ServeHTTP(w, req)

			// Check status
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestBucketAccessMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		isAdmin        bool
		expectedStatus int
	}{
		{
			name:           "admin access to any bucket",
			path:           "/restricted-bucket/file.txt",
			isAdmin:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user access to allowed bucket",
			path:           "/warehouse/file.txt",
			isAdmin:        false,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user access to forbidden bucket",
			path:           "/restricted-bucket/file.txt",
			isAdmin:        false,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "root path (no bucket)",
			path:           "/",
			isAdmin:        false,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Create middleware
			middleware := BucketAccessMiddleware()
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest("GET", tt.path, nil)
			
			// Set user context
			ctx := context.WithValue(req.Context(), "user_sub", "test-user")
			if tt.isAdmin {
				ctx = context.WithValue(ctx, "is_admin", true)
			}
			req = req.WithContext(ctx)

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			wrappedHandler.ServeHTTP(w, req)

			// Check status
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}