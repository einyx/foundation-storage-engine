package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/einyx/foundation-storage-engine/internal/cache"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/database"
	"github.com/einyx/foundation-storage-engine/internal/metrics"
	"github.com/einyx/foundation-storage-engine/internal/storage"
	"github.com/einyx/foundation-storage-engine/internal/virustotal"
	"github.com/einyx/foundation-storage-engine/pkg/s3"
)

type Server struct {
	config           *config.Config
	storage          storage.Backend
	auth             auth.Provider
	router           *mux.Router
	s3Handler        *s3.Handler
	metrics          *metrics.Metrics
	auth0            *Auth0Handler
	shareLinkHandler *ShareLinkHandler
	db               *database.DB // Database connection for auth
	scanner          *virustotal.Scanner
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

	// Create auth provider based on configuration
	var authProvider auth.Provider
	var db *database.DB
	
	if cfg.Auth.Type == "database" && cfg.Database.Enabled {
		// Initialize database connection for authentication
		dbConfig := database.Config{
			Driver:           cfg.Database.Driver,
			ConnectionString: cfg.Database.ConnectionString,
			MaxOpenConns:     cfg.Database.MaxOpenConns,
			MaxIdleConns:     cfg.Database.MaxIdleConns,
			ConnMaxLifetime:  cfg.Database.ConnMaxLifetime,
		}
		
		var err error
		db, err = database.NewConnection(dbConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create database connection: %w", err)
		}
		
		authProvider = auth.NewDatabaseProvider(db)
		logrus.Info("Database authentication provider initialized")
	} else {
		authProvider, err = auth.NewProvider(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth provider: %w", err)
		}
	}

	// Remove overhead
	// Skip limiters

	s := &Server{
		config:  cfg,
		storage: storageBackend,
		auth:    authProvider,
		router:  mux.NewRouter(),
		metrics: metrics.NewMetrics("foundation_storage_engine"),
		db:      db,
	}

	// Initialize Auth0 if enabled
	if cfg.Auth0.Enabled {
		s.auth0 = NewAuth0Handler(&cfg.Auth0)
	}
	
	// Initialize VirusTotal scanner
	scanner, err := virustotal.NewScanner(&cfg.VirusTotal)
	if err != nil {
		return nil, fmt.Errorf("failed to create VirusTotal scanner: %w", err)
	}
	s.scanner = scanner
	
	if scanner.IsEnabled() {
		logrus.Info("VirusTotal scanning enabled")
	}

	s.s3Handler = s3.NewHandler(s.storage, s.auth, cfg.S3, cfg.Chunking)
	s.s3Handler.SetScanner(s.scanner)
	
	// Initialize share link handler
	s.shareLinkHandler = NewShareLinkHandler(s.s3Handler)
	
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

func (s *Server) setupAPIDocumentation() {
	// Read the OpenAPI spec
	openAPISpec, err := os.ReadFile("api/openapi.yaml")
	if err != nil {
		logrus.WithError(err).Warn("Failed to load OpenAPI specification, API documentation will not be available")
		return
	}

	// Serve Swagger UI
	s.router.PathPrefix("/docs/").HandlerFunc(ServeSwaggerUI(openAPISpec)).Methods("GET")
	
	// Redirect /docs to /docs/
	s.router.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	}).Methods("GET")

	logrus.Info("API documentation available at /docs/")
}

func (s *Server) setupRoutes() {
	// Register monitoring endpoints first (highest priority)
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")
	s.router.Handle("/metrics", s.metrics.Handler()).Methods("GET")
	s.router.Handle("/stats", s.metrics.StatsHandler()).Methods("GET")
	
	// Register pprof endpoints if enabled
	if s.config.Monitoring.PprofEnabled {
		logrus.Info("pprof profiling endpoints enabled at /debug/pprof/")
		// Import registers handlers with DefaultServeMux, but we need to handle them directly
		s.router.HandleFunc("/debug/pprof/", pprof.Index)
		s.router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		s.router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		s.router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		s.router.HandleFunc("/debug/pprof/trace", pprof.Trace)
		s.router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		s.router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		s.router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
		s.router.Handle("/debug/pprof/block", pprof.Handler("block"))
		s.router.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
		s.router.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	}

	// Register API documentation endpoint
	s.setupAPIDocumentation()

	// Register Auth0 routes if enabled
	if s.config.Auth0.Enabled && s.auth0 != nil {
		logrus.Info("Auth0 authentication enabled")
		s.router.HandleFunc("/api/auth/login", s.auth0.LoginHandler).Methods("GET")
		s.router.HandleFunc("/api/auth/callback", s.auth0.CallbackHandler).Methods("GET")
		s.router.HandleFunc("/api/auth/logout", s.auth0.LogoutHandler).Methods("GET")
		s.router.HandleFunc("/api/auth/userinfo", s.auth0.UserInfoHandler).Methods("GET")
	}
	
	// Register auth validation endpoint
	s.router.HandleFunc("/api/auth/validate", s.validateCredentials).Methods("POST")
	
	// Register feature flags endpoint
	s.router.HandleFunc("/api/features", s.getFeatures).Methods("GET")
	
	// Register share link routes
	s.router.HandleFunc("/api/share/create", s.shareLinkHandler.CreateShareLinkHandler).Methods("POST")
	s.router.HandleFunc("/api/share/{shareID}", s.shareLinkHandler.ServeSharedFile).Methods("GET", "HEAD")

	// Register UI routes if enabled
	if s.config.UI.Enabled {
		logrus.WithFields(logrus.Fields{
			"basePath": s.config.UI.BasePath,
			"staticPath": s.config.UI.StaticPath,
		}).Info("Web UI enabled")
		
		// Serve static files from the UI path
		fileServer := http.FileServer(http.Dir(s.config.UI.StaticPath))
		s.router.PathPrefix(s.config.UI.BasePath + "/").Handler(
			http.StripPrefix(s.config.UI.BasePath, fileServer),
		).Methods("GET")
		
		// Redirect /ui to /ui/
		s.router.HandleFunc(s.config.UI.BasePath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, s.config.UI.BasePath+"/", http.StatusMovedPermanently)
		}).Methods("GET")
	}

	// Register S3 bucket operations (must be after monitoring endpoints and UI)
	s.router.HandleFunc("/", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket}", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket}/", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket}/{key:.+}", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
}

func (s *Server) handleS3Request(w http.ResponseWriter, r *http.Request) {
	// Handle virtual-hosted-style requests
	// Extract bucket from Host header if it matches pattern: bucket.s3.domain
	host := r.Host
	if strings.Contains(host, ".s3.") {
		parts := strings.Split(host, ".")
		if len(parts) >= 3 && parts[1] == "s3" {
			bucket := parts[0]
			// Rewrite the request to path-style
			if r.URL.Path == "/" {
				r.URL.Path = "/" + bucket + "/"
			} else {
				r.URL.Path = "/" + bucket + r.URL.Path
			}
			// Update mux vars
			vars := mux.Vars(r)
			if vars == nil {
				vars = make(map[string]string)
			}
			vars["bucket"] = bucket
			r = mux.SetURLVars(r, vars)
			
			logrus.WithFields(logrus.Fields{
				"host": host,
				"bucket": bucket,
				"rewrittenPath": r.URL.Path,
			}).Debug("Converted virtual-hosted-style to path-style")
		}
	}
	
	logrus.WithFields(logrus.Fields{
		"path": r.URL.Path,
		"authType": s.config.Auth.Type,
		"hasAuth": r.Header.Get("Authorization") != "",
		"contentLength": r.ContentLength,
		"contentLengthHeader": r.Header.Get("Content-Length"),
	}).Debug("handleS3Request called")
	
	if s.config.Auth.Type != "none" {
		// Allow unauthenticated access from UI
		referer := r.Header.Get("Referer")
		if strings.Contains(referer, "/ui/") {
			// Skip auth for UI requests
			logrus.WithField("referer", referer).Debug("Skipping auth for UI request")
		} else {
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
		
		// Remove Authorization header after successful authentication
		// to prevent it from being forwarded to the backend S3
		logrus.WithFields(logrus.Fields{
			"path": r.URL.Path,
			"hadAuth": r.Header.Get("Authorization") != "",
		}).Debug("Removing auth headers after successful authentication")
		
		r.Header.Del("Authorization")
		r.Header.Del("X-Amz-Security-Token")
		r.Header.Del("X-Amz-Credential")
		r.Header.Del("X-Amz-Date")
		r.Header.Del("X-Amz-SignedHeaders")
		r.Header.Del("X-Amz-Signature")
		
		logrus.WithFields(logrus.Fields{
			"path": r.URL.Path,
			"hasAuthAfter": r.Header.Get("Authorization") != "",
		}).Debug("Auth headers removed")
	}

	// Log request for debugging - commented out for production
	// if logrus.GetLevel() >= logrus.DebugLevel {
	// 	logrus.WithFields(logrus.Fields{
	// 		"method": r.Method,
	// 		"path":   r.URL.Path,
	// 		"query":  r.URL.RawQuery,
	// 	}).Debug("Passing request to S3 handler")
	// }

	// Debug log before passing to S3 handler
	logrus.WithFields(logrus.Fields{
		"path": r.URL.Path,
		"contentLength": r.ContentLength,
		"contentLengthHeader": r.Header.Get("Content-Length"),
		"method": r.Method,
	}).Debug("Passing to S3 handler")

	// Pass to S3 handler
	s.s3Handler.ServeHTTP(w, r)
}

func (s *Server) healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}

// validateCredentials validates S3-compatible credentials
func (s *Server) validateCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Parse JSON request body
	var creds struct {
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Invalid request body"}`))
		return
	}
	
	// Validate credentials based on auth type
	switch s.config.Auth.Type {
	case "awsv4", "awsv2":
		// Check if credentials match configured values
		if creds.AccessKey == s.config.Auth.Identity && creds.SecretKey == s.config.Auth.Credential {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"valid":true,"message":"Credentials valid"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"valid":false,"message":"Invalid credentials"}`))
		}
	case "database":
		// For database auth, check against database
		if dbProvider, ok := s.auth.(*auth.DatabaseProvider); ok {
			secretKey, err := dbProvider.GetSecretKey(creds.AccessKey)
			if err != nil || secretKey != creds.SecretKey {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"valid":false,"message":"Invalid credentials"}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"valid":true,"message":"Credentials valid"}`))
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"Database auth not properly configured"}`))
		}
	case "none":
		// No auth required
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"valid":true,"message":"No authentication required"}`))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"Unknown auth type"}`))
	}
}

// getFeatures returns the enabled features/modules
func (s *Server) getFeatures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	features := map[string]interface{}{
		"virustotal": map[string]interface{}{
			"enabled": s.config.VirusTotal.Enabled,
			"scanUploads": s.config.VirusTotal.ScanUploads,
			"blockThreats": s.config.VirusTotal.BlockThreats,
			"maxFileSize": s.config.VirusTotal.MaxFileSize,
		},
		"auth0": map[string]interface{}{
			"enabled": s.config.Auth0.Enabled,
		},
		"ui": map[string]interface{}{
			"enabled": s.config.UI.Enabled,
		},
		"shareLinks": map[string]interface{}{
			"enabled": s.config.ShareLinks.Enabled,
		},
	}
	
	jsonData, err := json.Marshal(features)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"Failed to marshal features"}`))
		return
	}
	
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonData)
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

// Close cleanly shuts down the server and releases resources
func (s *Server) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
