package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/sirupsen/logrus"
)

// SentryMiddleware creates a new Sentry middleware for capturing panics and errors
func SentryMiddleware(repanic bool) func(http.Handler) http.Handler {
	sentryHandler := sentryhttp.New(sentryhttp.Options{
		Repanic:         repanic,
		WaitForDelivery: false,
		Timeout:         2 * time.Second,
	})

	return func(next http.Handler) http.Handler {
		return sentryHandler.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a wrapped response writer to capture status codes
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Add request info to Sentry scope
			if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
				hub.Scope().SetRequest(r)
				hub.Scope().SetTag("http.method", r.Method)
				hub.Scope().SetTag("http.path", r.URL.Path)
				hub.Scope().SetTag("http.remote_addr", r.RemoteAddr)
				
				// Add user context if available
				if userID := r.Header.Get("X-User-ID"); userID != "" {
					hub.Scope().SetUser(sentry.User{
						ID: userID,
					})
				}
			}

			// Process the request
			next.ServeHTTP(wrapped, r)

			// Capture HTTP errors (5xx)
			if wrapped.statusCode >= 500 {
				if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
					hub.WithScope(func(scope *sentry.Scope) {
						scope.SetLevel(sentry.LevelError)
						hub.CaptureMessage(fmt.Sprintf("HTTP %d: %s %s", wrapped.statusCode, r.Method, r.URL.Path))
					})
				}
			}
		}))
	}
}

// SentryRecoveryMiddleware captures panics and sends them to Sentry
func SentryRecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic
					logrus.WithFields(logrus.Fields{
						"error":  err,
						"method": r.Method,
						"path":   r.URL.Path,
					}).Error("Panic recovered")

					// Send to Sentry
					if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
						hub.RecoverWithContext(r.Context(), err)
						hub.Flush(2 * time.Second)
					} else {
						// If no hub in context, capture directly
						sentry.CurrentHub().RecoverWithContext(r.Context(), err)
						sentry.Flush(2 * time.Second)
					}

					// Return 500 error
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			
			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status codes
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// CaptureError captures an error to Sentry with additional context
func CaptureError(ctx context.Context, err error, tags map[string]string, extra map[string]interface{}) {
	if err == nil {
		return
	}

	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}

	// Clone hub to avoid modifying the original scope
	hub = hub.Clone()
	
	// Add tags
	for k, v := range tags {
		hub.Scope().SetTag(k, v)
	}

	// Add extra context
	for k, v := range extra {
		hub.Scope().SetContext(k, map[string]interface{}{
			"value": v,
		})
	}

	// Capture the error
	hub.CaptureException(err)
}

// CaptureMessage captures a message to Sentry with additional context
func CaptureMessage(ctx context.Context, message string, level sentry.Level, tags map[string]string, extra map[string]interface{}) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}

	// Clone hub to avoid modifying the original scope
	hub = hub.Clone()
	
	// Add tags
	for k, v := range tags {
		hub.Scope().SetTag(k, v)
	}

	// Add extra context
	for k, v := range extra {
		hub.Scope().SetContext(k, map[string]interface{}{
			"value": v,
		})
	}

	// Capture the message
	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(level)
		hub.CaptureMessage(message)
	})
}

// AddBreadcrumb adds a breadcrumb to the current Sentry scope
func AddBreadcrumb(ctx context.Context, breadcrumb *sentry.Breadcrumb) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	
	hub.Scope().AddBreadcrumb(breadcrumb, 0)
}