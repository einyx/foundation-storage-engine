package proxy

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/einyx/foundation-storage-engine/internal/cache"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/metrics"
	"github.com/einyx/foundation-storage-engine/internal/storage"
	"github.com/einyx/foundation-storage-engine/pkg/s3"
)

type Server struct {
	config    *config.Config
	storage   storage.Backend
	auth      auth.Provider
	router    *mux.Router
	s3Handler *s3.Handler
	metrics   *metrics.Metrics
}

// NewServer creates a new proxy server instance
func NewServer(cfg *config.Config) (*Server, error) {
	storageBackend, err := storage.NewBackend(cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Wrap with caching if enabled
	if cacheEnabled := os.Getenv("ENABLE_OBJECT_CACHE"); cacheEnabled == "true" {
		maxMemory := int64(1024 * 1024 * 1024) // 1GB default
		if envMem := os.Getenv("CACHE_MAX_MEMORY"); envMem != "" {
			if parsed, parseErr := strconv.ParseInt(envMem, 10, 64); parseErr == nil {
				maxMemory = parsed
			}
		}

		maxObjectSize := int64(10 * 1024 * 1024) // 10MB default
		if envSize := os.Getenv("CACHE_MAX_OBJECT_SIZE"); envSize != "" {
			if parsed, parseErr := strconv.ParseInt(envSize, 10, 64); parseErr == nil {
				maxObjectSize = parsed
			}
		}

		ttl := 5 * time.Minute // 5 minutes default
		if envTTL := os.Getenv("CACHE_TTL"); envTTL != "" {
			if parsed, parseErr := time.ParseDuration(envTTL); parseErr == nil {
				ttl = parsed
			}
		}

		objectCache, cacheErr := cache.NewObjectCache(maxMemory, maxObjectSize, ttl)
		if cacheErr != nil {
			logrus.WithError(cacheErr).Warn("Failed to create object cache, continuing without cache")
		} else {
			logrus.WithFields(logrus.Fields{
				"maxMemory":     maxMemory,
				"maxObjectSize": maxObjectSize,
				"ttl":           ttl,
			}).Info("Object caching enabled")
			storageBackend = cache.NewCachingBackend(storageBackend, objectCache)
		}
	}

	authProvider, err := auth.NewProvider(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth provider: %w", err)
	}

	// Remove overhead
	// Skip limiters

	s := &Server{
		config:  cfg,
		storage: storageBackend,
		auth:    authProvider,
		router:  mux.NewRouter(),
		metrics: metrics.NewMetrics("foundation_storage_engine"),
	}

	s.s3Handler = s3.NewHandler(s.storage, s.auth, cfg.S3, cfg.Chunking)
	s.setupRoutes()

	// Apply metrics middleware to all routes
	s.router.Use(s.metrics.Middleware())

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Preprocess request to fix mc client issues
	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "minio") || strings.Contains(strings.ToLower(userAgent), "mc") {
		// Try to fix authorization header before routing
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			cleanedHeader := strings.ReplaceAll(authHeader, "\n", "")
			cleanedHeader = strings.ReplaceAll(cleanedHeader, "\r", "")
			if cleanedHeader != authHeader {
				r.Header.Set("Authorization", cleanedHeader)
				// logrus.WithField("path", r.URL.Path).Debug("Cleaned MC auth header at ServeHTTP level")
			}
		}
	}

	s.router.ServeHTTP(w, r)
}

func (s *Server) setupRoutes() {
	// Register monitoring endpoints first (highest priority)
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")
	s.router.Handle("/metrics", s.metrics.Handler()).Methods("GET")
	s.router.Handle("/stats", s.metrics.StatsHandler()).Methods("GET")

	// Register S3 bucket operations (must be after monitoring endpoints)
	s.router.HandleFunc("/", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket}", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket}/", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket}/{key:.+}", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
}

func (s *Server) handleS3Request(w http.ResponseWriter, r *http.Request) {
	if s.config.Auth.Type != "none" {
		userAgent := r.Header.Get("User-Agent")
		if strings.Contains(strings.ToLower(userAgent), "minio") || strings.Contains(strings.ToLower(userAgent), "mc") {
			authHeader := r.Header.Get("Authorization")

			if strings.Contains(authHeader, "\n") || strings.Contains(authHeader, "\r") {
				cleanedHeader := strings.ReplaceAll(authHeader, "\n", "")
				cleanedHeader = strings.ReplaceAll(cleanedHeader, "\r", "")
				r.Header.Set("Authorization", cleanedHeader)

				// logrus.WithFields(logrus.Fields{
				// 	"originalLen": len(authHeader),
				// 	"cleanedLen":  len(cleanedHeader),
				// 	"path":        r.URL.Path,
				// }).Debug("Cleaned MC client auth header")
			}
		}

		if err := s.auth.Authenticate(r); err != nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
			return
		}
	}

	// Log request for debugging - commented out for production
	// if logrus.GetLevel() >= logrus.DebugLevel {
	// 	logrus.WithFields(logrus.Fields{
	// 		"method": r.Method,
	// 		"path":   r.URL.Path,
	// 		"query":  r.URL.RawQuery,
	// 	}).Debug("Passing request to S3 handler")
	// }

	// Pass to S3 handler
	s.s3Handler.ServeHTTP(w, r)
}

func (s *Server) healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}

// loggingMiddleware is currently unused but kept for future use
//
//nolint:unused
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fast path: skip logging for health checks
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Only log in debug mode for performance - commented out for production
		// if logrus.GetLevel() >= logrus.DebugLevel {
		// 	logger := logrus.WithFields(logrus.Fields{
		// 		"method": r.Method,
		// 		"path":   r.URL.Path,
		// 		"remote": r.RemoteAddr,
		// 	})
		// 	// logger.Debug("Request received")

		// 	next.ServeHTTP(w, r)

		// 	logger.Info("Request completed")
		// } else {
		next.ServeHTTP(w, r)
		// }
	})
}

// authMiddleware is no longer used - auth is handled inline in setupRoutes
//
//nolint:unused
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Ultra-fast path: inline auth check
		if s.auth == nil || s.config.Auth.Type == "none" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for authorization
		if err := s.auth.Authenticate(r); err != nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware is currently unused but kept for future use
//
//nolint:unused
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-amz-*")
		w.Header().Set("Access-Control-Expose-Headers", "ETag, x-amz-*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
