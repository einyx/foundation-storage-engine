package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/sirupsen/logrus"
)

// AuthenticationMiddleware validates S3 request authentication
func AuthenticationMiddleware(authProvider auth.Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication if already authenticated at proxy level
			if isAuthenticated := r.Context().Value("authenticated"); isAuthenticated != nil {
				if authenticated, ok := isAuthenticated.(bool); ok && authenticated {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Perform authentication
			if err := authProvider.Authenticate(r); err != nil {
				logrus.WithFields(logrus.Fields{
					"method": r.Method,
					"path":   r.URL.Path,
					"error":  err,
				}).Warn("Authentication failed in S3 handler")
				
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Add authentication flag to context
			ctx := context.WithValue(r.Context(), "authenticated", true)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// AdminAuthMiddleware enforces admin privileges
func AdminAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if user is admin from context
			isAdmin := false
			if adminValue := r.Context().Value("is_admin"); adminValue != nil {
				if admin, ok := adminValue.(bool); ok {
					isAdmin = admin
				}
			}

			if !isAdmin {
				logrus.WithFields(logrus.Fields{
					"method": r.Method,
					"path":   r.URL.Path,
				}).Warn("Admin access required but user is not admin")
				
				http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// BucketAccessMiddleware controls bucket access permissions
func BucketAccessMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract bucket name from URL path
			pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(pathParts) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			bucket := pathParts[0]
			if bucket == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if user has access to this bucket
			userSub := r.Context().Value("user_sub")
			isAdmin := r.Context().Value("is_admin")

			// Admin users have access to all buckets
			if adminValue, ok := isAdmin.(bool); ok && adminValue {
				next.ServeHTTP(w, r)
				return
			}

			// For non-admin users, allow access to any bucket that exists
			// This allows dynamic bucket creation without hardcoded lists
			logrus.WithFields(logrus.Fields{
				"bucket":   bucket,
				"user_sub": userSub,
				"method":   r.Method,
				"path":     r.URL.Path,
			}).Debug("Allowing bucket access for authenticated user")

			next.ServeHTTP(w, r)
		})
	}
}