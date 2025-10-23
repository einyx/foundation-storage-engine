// Package s3 provides S3-compatible API handlers for the proxy server.
package s3

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/middleware"
	"github.com/einyx/foundation-storage-engine/internal/storage"
	"github.com/einyx/foundation-storage-engine/internal/virustotal"
)

const (
	smallBufferSize  = 4 * 1024    // 4KB
	mediumBufferSize = 256 * 1024  // 256KB - increased for better large file handling
	largeBufferSize  = 1024 * 1024 // 1MB - for very large files
	smallFileLimit   = 100 * 1024  // 100KB
)

var (
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, smallBufferSize)
			return &buf
		},
	}
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, mediumBufferSize)
			return &buf
		},
	}
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, largeBufferSize)
			return &buf
		},
	}
)

// Handler represents the S3-compatible HTTP handler
type Handler struct {
	storage  storage.Backend
	auth     auth.Provider
	config   config.S3Config
	router   *mux.Router
	chunking config.ChunkingConfig
	scanner  *virustotal.Scanner
}

// NewHandler creates a new S3 handler instance
func NewHandler(storage storage.Backend, auth auth.Provider, cfg config.S3Config, chunking config.ChunkingConfig) *Handler {
	h := &Handler{
		storage:  storage,
		auth:     auth,
		config:   cfg,
		router:   mux.NewRouter(),
		chunking: chunking,
		scanner:  nil, // Scanner is optional, set with SetScanner
	}

	h.setupRoutes()
	return h
}

// SetScanner sets the VirusTotal scanner for the handler
func (h *Handler) SetScanner(scanner *virustotal.Scanner) {
	h.scanner = scanner
}

// ServeHTTP handles all S3 requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Add S3-compatible headers early to help clients recognize this as S3
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", fmt.Sprintf("%d", start.UnixNano()))

	// Wrap response writer to capture status
	wrapped := &responseWriter{
		ResponseWriter: w,
		statusCode:     200,
		written:        false,
	}

	logrus.WithFields(logrus.Fields{
		"method":       r.Method,
		"path":         r.URL.Path,
		"query":        r.URL.RawQuery,
		"userAgent":    r.Header.Get("User-Agent"),
		"has_auth":     r.Header.Get("Authorization") != "",
		"has_amz_date": r.Header.Get("X-Amz-Date") != "",
		"all_headers":  r.Header,
	}).Info("Incoming S3 request")

	h.router.ServeHTTP(wrapped, r)

	// Log response
	duration := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"method":   r.Method,
		"path":     r.URL.Path,
		"status":   wrapped.statusCode,
		"duration": duration,
	}).Info("S3 request completed")
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *responseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// setupRoutes configures all S3 API routes
func (h *Handler) setupRoutes() {
	// Apply authentication middleware to all routes
	authMiddleware := middleware.AuthenticationMiddleware(h.auth)
	bucketAccessMiddleware := middleware.BucketAccessMiddleware()
	adminMiddleware := middleware.AdminAuthMiddleware()

	// Service operations (requires authentication) - EXACT match for root
	h.router.Handle("/", authMiddleware(http.HandlerFunc(h.listBuckets))).Methods("GET")
	h.router.HandleFunc("/", h.handleOptions).Methods("OPTIONS")

	// Bucket operations (requires authentication + bucket access)
	bucketAuth := func(h http.HandlerFunc) http.Handler {
		return authMiddleware(bucketAccessMiddleware(h))
	}

	// Admin bucket operations
	adminAuth := func(h http.HandlerFunc) http.Handler {
		return authMiddleware(adminMiddleware(bucketAccessMiddleware(h)))
	}

	// Object routes - ensure bucket name is not empty (MUST come first for proper matching)
	h.router.Handle("/{bucket:[^/]+}/{key:.+}", bucketAuth(h.handleObject)).Methods("GET", "PUT", "DELETE", "HEAD", "POST")

	// Bucket admin routes - ensure bucket name is not empty
	h.router.Handle("/{bucket:[^/]+}", adminAuth(h.handleBucketAdmin)).Methods("PUT", "DELETE")
	h.router.Handle("/{bucket:[^/]+}/", adminAuth(h.handleBucketAdmin)).Methods("PUT", "DELETE")

	// Regular bucket routes - ensure bucket name is not empty
	h.router.Handle("/{bucket:[^/]+}", bucketAuth(h.handleBucket)).Methods("GET", "HEAD", "POST")
	h.router.Handle("/{bucket:[^/]+}/", bucketAuth(h.handleBucket)).Methods("GET", "HEAD", "POST")
}

// handleOptions handles CORS preflight requests
func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Amz-*, Accept, X-Requested-With")
	w.Header().Set("Access-Control-Max-Age", "86400")

	w.WriteHeader(http.StatusOK)
}

// isListOperation checks if a GET request should be treated as a list operation
// based on query parameters that indicate a bucket listing rather than object retrieval
func (h *Handler) isListOperation(r *http.Request) bool {
	query := r.URL.Query()

	// Check for list-type query parameters that indicate this is a list operation
	listParams := []string{
		"list-type",          // S3 v2 list API
		"delimiter",          // Directory-style listing
		"prefix",             // Prefix filtering
		"marker",             // S3 v1 list continuation
		"max-keys",           // Limit number of results
		"continuation-token", // S3 v2 list continuation
	}

	for _, param := range listParams {
		if query.Has(param) {
			return true
		}
	}

	return false
}

// isValidBucket validates bucket name according to S3 naming rules and checks existence
func (h *Handler) isValidBucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 {
		return false
	}
	if strings.Contains(bucket, "..") {
		return false
	}

	// Check if bucket exists in storage
	ctx := context.Background()
	exists, err := h.storage.BucketExists(ctx, bucket)
	if err != nil {
		return false
	}
	return exists
}

// getClientIP extracts client IP from X-Forwarded-For header or request
func (h *Handler) getClientIP(xForwardedFor string) string {
	if xForwardedFor != "" {
		// X-Forwarded-For may contain multiple IPs, take the first one
		if idx := strings.Index(xForwardedFor, ","); idx != -1 {
			return strings.TrimSpace(xForwardedFor[:idx])
		}
		return strings.TrimSpace(xForwardedFor)
	}

	return ""
}

// isResponseStarted checks if response has already been written
func isResponseStarted(w http.ResponseWriter) bool {
	if rw, ok := w.(*responseWriter); ok {
		return rw.written
	}
	return false
}

// noBucketMatcher is a custom matcher for routes that should not match bucket paths
func noBucketMatcher(r *http.Request, rm *mux.RouteMatch) bool {
	// Only match if this is exactly "/" (no bucket name)
	return r.URL.Path == "/"
}

// sendError sends a structured error response in S3-compatible XML format.
func (h *Handler) sendError(w http.ResponseWriter, err error, status int) {
	type errorResponse struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}

	code := "InternalError"
	switch status {
	case http.StatusNotFound:
		code = "NoSuchKey"
	case http.StatusConflict:
		code = "BucketAlreadyExists"
	case http.StatusBadRequest:
		code = "BadRequest"
	case http.StatusForbidden:
		code = "AccessDenied"
	case http.StatusUnauthorized:
		code = "SignatureDoesNotMatch"
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if encErr := enc.Encode(errorResponse{
		Code:    code,
		Message: err.Error(),
	}); encErr != nil {
		logrus.WithError(encErr).Error("Failed to encode error response")
	}
}

// isClientDisconnectError checks if error is due to client disconnect.
func isClientDisconnectError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "client disconnected") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "write: connection refused")
}
