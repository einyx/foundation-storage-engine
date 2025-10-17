package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/einyx/foundation-storage-engine/internal/cache"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/database"
	"github.com/einyx/foundation-storage-engine/internal/metrics"
	"github.com/einyx/foundation-storage-engine/internal/middleware"
	"github.com/einyx/foundation-storage-engine/internal/storage"
	"github.com/einyx/foundation-storage-engine/internal/virustotal"
	"github.com/einyx/foundation-storage-engine/pkg/s3"
)

const (
	// Cache configuration constants
	defaultMaxMemory     = 1024 * 1024 * 1024 // 1GB
	defaultMaxObjectSize = 10 * 1024 * 1024   // 10MB
	defaultCacheTTL      = 5 * time.Minute
)

// responseRecorder captures HTTP response for debugging
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *strings.Builder
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	// Don't write header yet - we'll do it manually later
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	// Don't write to the underlying ResponseWriter here - we'll do it manually later
	return len(b), nil
}

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
	shuttingDown     int32 // atomic flag for shutdown state
}

// NewServer initializes proxy server with configured storage backend
func NewServer(cfg *config.Config) (*Server, error) {
	storageBackend, err := storage.NewBackend(cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Wrap with caching if enabled
	if cacheEnabled := os.Getenv("ENABLE_OBJECT_CACHE"); cacheEnabled == "true" {
		maxMemory := int64(defaultMaxMemory)
		if envMem := os.Getenv("CACHE_MAX_MEMORY"); envMem != "" {
			if parsed, parseErr := strconv.ParseInt(envMem, 10, 64); parseErr == nil {
				maxMemory = parsed
			}
		}

		maxObjectSize := int64(defaultMaxObjectSize)
		if envSize := os.Getenv("CACHE_MAX_OBJECT_SIZE"); envSize != "" {
			if parsed, parseErr := strconv.ParseInt(envSize, 10, 64); parseErr == nil {
				maxObjectSize = parsed
			}
		}

		ttl := defaultCacheTTL
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

		baseProvider := auth.NewDatabaseProvider(db)
		
		// Wrap with OPA if enabled
		if cfg.OPA.Enabled {
			authProvider = auth.NewOPAProvider(cfg.Auth, cfg.OPA, baseProvider)
			logrus.WithField("opa_url", cfg.OPA.URL).Info("Database authentication provider initialized with OPA authorization")
		} else {
			authProvider = baseProvider
			logrus.Info("Database authentication provider initialized")
		}
	} else {
		authProvider, err = auth.NewProviderWithOPA(cfg.Auth, cfg.OPA)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth provider: %w", err)
		}
		
		if cfg.OPA.Enabled {
			logrus.WithField("opa_url", cfg.OPA.URL).Info("Authentication provider initialized with OPA authorization")
		} else {
			logrus.Info("Authentication provider initialized")
		}
	}


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

	// Apply middleware to all routes
	s.router.Use(s.metrics.Middleware())
	
	// Apply Sentry middleware if enabled
	if s.config.Sentry.Enabled {
		s.router.Use(middleware.SentryRecoveryMiddleware())
		s.router.Use(middleware.SentryMiddleware(false))
		logrus.Info("Sentry middleware enabled")
	}

	return s, nil
}

// ServeHTTP handles incoming requests with security headers and preprocessing
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add security headers to all responses
	s.setSecurityHeaders(w)

	// Preprocess request to fix mc client issues
	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "minio") || strings.Contains(strings.ToLower(userAgent), "mc") {
		// Try to fix authorization header before routing
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			cleanedHeader := strings.ReplaceAll(authHeader, "\n", "")
			cleanedHeader = strings.ReplaceAll(cleanedHeader, "\r", "")
			if cleanedHeader != authHeader {
				r.Header.Set("Authorization", cleanedHeader)
			}
		}
	}

	s.router.ServeHTTP(w, r)
}

// setSecurityHeaders applies security headers
func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	// Prevent clickjacking attacks
	w.Header().Set("X-Frame-Options", "DENY")

	// Prevent MIME type sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Enable XSS filter in older browsers
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Enforce HTTPS - Always set HSTS header as TLS termination might be handled by a reverse proxy
	// max-age=31536000 (1 year), includeSubDomains
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Content Security Policy - restrictive by default
	// Allow self for scripts/styles, data: for images (base64), and 'unsafe-inline' for styles (needed by some UI frameworks)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://browser.sentry-cdn.com https://*.sentry.io https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' https://*.sentry.io; frame-src 'self' https://*.sentry.io; frame-ancestors 'none';")

	// Referrer Policy - don't leak referrer information
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Permissions Policy (formerly Feature Policy) - disable unnecessary features
	w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
}

func (s *Server) setupAPIDocumentation() {
	// Read the OpenAPI spec
	openAPISpec, err := os.ReadFile("api/openapi.yaml")
	if err != nil {
		logrus.WithError(err).Warn("Failed to load OpenAPI specification, API documentation will not be available")
		return
	}

	// Serve Swagger UI at both /docs/ and /api/docs/
	s.router.PathPrefix("/docs/").HandlerFunc(ServeSwaggerUI(openAPISpec, "/docs")).Methods("GET")
	s.router.PathPrefix("/api/docs/").HandlerFunc(ServeSwaggerUI(openAPISpec, "/api/docs")).Methods("GET")

	// Redirect /docs to /docs/ and /api/docs to /api/docs/
	s.router.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	}).Methods("GET")
	s.router.HandleFunc("/api/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/docs/", http.StatusMovedPermanently)
	}).Methods("GET")

	logrus.Info("API documentation available at /docs/ and /api/docs/")
}

func (s *Server) setupRoutes() {
	// Register monitoring endpoints first (highest priority)
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET", "HEAD")
	s.router.HandleFunc("/ready", s.readinessCheck).Methods("GET", "HEAD")
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
		s.router.HandleFunc("/api/auth/status", s.auth0.AuthStatusHandler).Methods("GET")
		
		// API Key management endpoints
		s.router.HandleFunc("/api/auth/keys", s.auth0.CreateAPIKeyHandler).Methods("POST")
		s.router.HandleFunc("/api/auth/keys", s.auth0.ListAPIKeysHandler).Methods("GET")
		s.router.HandleFunc("/api/auth/keys/revoke", s.auth0.RevokeAPIKeyHandler).Methods("POST")
		
		// Admin endpoints for group/role management
		adminHandlers := NewAdminHandlers(s.auth0)
		s.router.HandleFunc("/api/admin/group-mappings", adminHandlers.ListGroupMappingsHandler).Methods("GET")
		s.router.HandleFunc("/api/admin/group-mappings", adminHandlers.CreateGroupMappingHandler).Methods("POST")
		s.router.HandleFunc("/api/admin/group-mappings", adminHandlers.DeleteGroupMappingHandler).Methods("DELETE")
		s.router.HandleFunc("/api/admin/effective-roles", adminHandlers.GetEffectiveRolesHandler).Methods("GET")
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
			"basePath":   s.config.UI.BasePath,
			"staticPath": s.config.UI.StaticPath,
			"auth0":      s.config.Auth0.Enabled,
		}).Info("Web UI enabled")

		if s.config.Auth0.Enabled && s.auth0 != nil {
			// Serve secure UI with Auth0 authentication
			s.router.HandleFunc(s.config.UI.BasePath, s.auth0.SecureUIHandler).Methods("GET")
			s.router.HandleFunc(s.config.UI.BasePath+"/", s.auth0.SecureUIHandler).Methods("GET")
			
			// Block unsafe static files that bypass auth
			s.router.HandleFunc(s.config.UI.BasePath + "/login.html", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
			}).Methods("GET")
			s.router.HandleFunc(s.config.UI.BasePath + "/index.html", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, s.config.UI.BasePath, http.StatusTemporaryRedirect)
			}).Methods("GET")
			
			// Add profile page route
			s.router.HandleFunc(s.config.UI.BasePath + "/profile", s.auth0.ProfileHandler).Methods("GET")
			
			// Add admin page route (protected)
			s.router.HandleFunc(s.config.UI.BasePath + "/admin", s.serveAdminUI).Methods("GET")
			
			// Protected static assets - these should be served without auth middleware
			// but the session check will happen on the main UI pages that load these assets
			s.router.PathPrefix(s.config.UI.BasePath + "/js/").Handler(
				http.StripPrefix(s.config.UI.BasePath, s.uiHandler()),
			).Methods("GET")
			s.router.PathPrefix(s.config.UI.BasePath + "/css/").Handler(
				http.StripPrefix(s.config.UI.BasePath, s.uiHandler()),
			).Methods("GET")
			s.router.HandleFunc(s.config.UI.BasePath + "/browser.html", s.auth0.RequireUIAuth(s.uiHandler().ServeHTTP)).Methods("GET")

			logrus.Info("UI protected with Auth0 authentication")
		} else {
			// Serve UI without authentication
			s.router.PathPrefix(s.config.UI.BasePath + "/").Handler(
				http.StripPrefix(s.config.UI.BasePath, s.uiHandler()),
			).Methods("GET")

			// Redirect /ui to /ui/
			s.router.HandleFunc(s.config.UI.BasePath, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, s.config.UI.BasePath+"/", http.StatusMovedPermanently)
			}).Methods("GET")
		}
	}

	// Handle common web files that should not be treated as S3 buckets
	commonWebFiles := []string{"/favicon.ico", "/robots.txt", "/.well-known", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"}
	for _, path := range commonWebFiles {
		s.router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}).Methods("GET", "HEAD")
	}

	// Add explicit exclusions for known non-bucket paths BEFORE S3 routes
	// Only exclude paths that might be interpreted as bucket names but shouldn't be
	excludedPaths := []string{"api", "recent", "admin", "features"}
	for _, path := range excludedPaths {
		// Handle both /path and /path/* to catch all sub-paths
		s.router.HandleFunc("/"+path, func(w http.ResponseWriter, r *http.Request) {
			logrus.WithField("excluded_path", r.URL.Path).Debug("Explicitly excluded path")
			http.NotFound(w, r)
		}).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
		s.router.PathPrefix("/"+path+"/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.WithField("excluded_path", r.URL.Path).Debug("Explicitly excluded sub-path")
			http.NotFound(w, r)
		}).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	}

	// Register S3 bucket operations (must be after exclusions)
	// Use simple patterns that explicitly exclude known paths
	s.router.HandleFunc("/", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	
	// Simple bucket patterns without complex regex
	s.router.HandleFunc("/{bucket:[a-zA-Z0-9._-]+}", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket:[a-zA-Z0-9._-]+}/", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	s.router.HandleFunc("/{bucket:[a-zA-Z0-9._-]+}/{key:.+}", s.handleS3Request).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	
	// Add debug handler to catch unmatched routes
	s.router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"method": r.Method,
			"query":  r.URL.RawQuery,
		}).Warn("Route not found - 404")
		http.NotFound(w, r)
	})
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
				"host":          host,
				"bucket":        bucket,
				"rewrittenPath": r.URL.Path,
			}).Debug("Converted virtual-hosted-style to path-style")
		}
	}

	logrus.WithFields(logrus.Fields{
		"path":                r.URL.Path,
		"method":              r.Method,
		"authType":            s.config.Auth.Type,
		"hasAuth":             r.Header.Get("Authorization") != "",
		"contentLength":       r.ContentLength,
		"contentLengthHeader": r.Header.Get("Content-Length"),
		"userAgent":           r.Header.Get("User-Agent"),
		"accept":              r.Header.Get("Accept"),
	}).Info("S3 request received")

	if s.config.Auth.Type != "none" {
		// Allow unauthenticated access to monitoring endpoints and docs
		isPublicPath := s.isPublicPath(r.URL.Path)
		isUIPath := strings.HasPrefix(r.URL.Path, "/ui/") || r.URL.Path == "/ui"

		logrus.WithFields(logrus.Fields{
			"path": r.URL.Path,
			"auth_type": s.config.Auth.Type,
			"is_public_path": isPublicPath,
			"is_ui_path": isUIPath,
		}).Info("Proxy authentication check starting")

		authenticated := s.checkAuth0Session(r)

		if !authenticated && !isPublicPath {
			s.cleanMinIOClientHeaders(r)

			// For UI paths, redirect to Auth0 login - don't try AWS auth
			if isUIPath {
				if s.auth0 != nil && s.auth0.config.Enabled {
					// Let Auth0 middleware handle the redirect
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}

			// Try API key authentication for S3 operations
			if !authenticated {
				authenticated = s.tryAPIKeyAuth(r)
			}

			// For S3 operations (non-UI paths), require AWS signature authentication
			if !authenticated && !isUIPath {
				if err := s.auth.Authenticate(r); err != nil {
					logrus.WithFields(logrus.Fields{
						"path": r.URL.Path,
						"method": r.Method,
						"error": err.Error(),
					}).Warn("AWS signature authentication failed")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
					return
				}
				// AWS authentication succeeded
				authenticated = true
			}
			
			// Store user context if we have Auth0 info for UI operations
			if authenticated && isUIPath && s.auth0 != nil {
				if session, err := s.auth0.store.Get(r, sessionName); err == nil {
					var userRoles []string
					if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
						userRoles = strings.Split(rolesStr, ",")
					}
					ctx := r.Context()
					ctx = context.WithValue(ctx, "user_roles", userRoles)
					ctx = context.WithValue(ctx, "user_sub", session.Values["user_sub"])
					ctx = context.WithValue(ctx, "is_admin", isAdminUser(userRoles))
					r = r.WithContext(ctx)
				}
			}
			
			// Set authenticated flag in context for S3 handler to skip re-authentication
			if authenticated || s.config.Auth.Type == "none" {
				ctx := r.Context()
				ctx = context.WithValue(ctx, "authenticated", true)
				r = r.WithContext(ctx)
			}
		}

		// Don't remove Authorization header for S3 requests - S3 handler needs it
		// Only remove auth headers for non-S3 operations (UI, API endpoints)
		if isUIPath || isPublicPath {
			logrus.WithFields(logrus.Fields{
				"path":    r.URL.Path,
				"hadAuth": r.Header.Get("Authorization") != "",
			}).Debug("Removing auth headers after successful authentication for non-S3 path")

			r.Header.Del("Authorization")
			r.Header.Del("X-Amz-Security-Token")
			r.Header.Del("X-Amz-Credential")
			r.Header.Del("X-Amz-Date")
			r.Header.Del("X-Amz-SignedHeaders")
			r.Header.Del("X-Amz-Signature")
		} else {
			logrus.WithFields(logrus.Fields{
				"path":    r.URL.Path,
				"hadAuth": r.Header.Get("Authorization") != "",
			}).Debug("Preserving auth headers for S3 request")
		}

		logrus.WithFields(logrus.Fields{
			"path":         r.URL.Path,
			"hasAuthAfter": r.Header.Get("Authorization") != "",
		}).Debug("Auth headers removed")
	}

	// }

	// Debug log before passing to S3 handler
	logrus.WithFields(logrus.Fields{
		"path":                r.URL.Path,
		"contentLength":       r.ContentLength,
		"contentLengthHeader": r.Header.Get("Content-Length"),
		"method":              r.Method,
	}).Debug("Passing to S3 handler")

	// Add CORS headers for all S3 requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Amz-*")
	
	// Pass to S3 handler normally (no more duplicate response)
	s.s3Handler.ServeHTTP(w, r)
}

func (s *Server) healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Check if server is shutting down
	isShuttingDown := atomic.LoadInt32(&s.shuttingDown) == 1
	
	// Add status headers
	if s.config.Sentry.Enabled {
		w.Header().Set("X-Sentry-Enabled", "true")
	} else {
		w.Header().Set("X-Sentry-Enabled", "false")
	}
	
	if isShuttingDown {
		w.Header().Set("X-Shutdown-Status", "in-progress")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"shutting-down","ready":false}`))
	} else {
		w.Header().Set("X-Shutdown-Status", "active")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","ready":true}`))
	}
}

// SetShuttingDown marks the server as shutting down
func (s *Server) SetShuttingDown() {
	atomic.StoreInt32(&s.shuttingDown, 1)
	logrus.Info("Server marked as shutting down - health checks will return 503")
}

// IsShuttingDown returns true if the server is shutting down
func (s *Server) IsShuttingDown() bool {
	return atomic.LoadInt32(&s.shuttingDown) == 1
}

// readinessCheck indicates if the server is ready to accept requests
func (s *Server) readinessCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if s.IsShuttingDown() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"ready":false,"status":"shutting-down"}`))
	} else {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true,"status":"active"}`))
	}
}

// uiHandler returns a handler that serves static files and processes HTML files
// to inject environment variables
func (s *Server) uiHandler() http.Handler {
	fileServer := http.FileServer(http.Dir(s.config.UI.StaticPath))
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is an HTML file
		if strings.HasSuffix(r.URL.Path, ".html") || r.URL.Path == "/" || r.URL.Path == "" {
			// Read the file
			filePath := r.URL.Path
			if filePath == "/" || filePath == "" {
				filePath = "/index.html"
			}
			
			fullPath := s.config.UI.StaticPath + filePath
			content, err := os.ReadFile(fullPath)
			if err != nil {
				if os.IsNotExist(err) {
					http.NotFound(w, r)
					return
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			
			// Replace placeholders with actual values
			html := string(content)
			html = strings.ReplaceAll(html, "{{SENTRY_ENABLED}}", strconv.FormatBool(s.config.Sentry.Enabled))
			html = strings.ReplaceAll(html, "{{SENTRY_DSN}}", s.config.Sentry.DSN)
			html = strings.ReplaceAll(html, "{{SENTRY_ENVIRONMENT}}", s.config.Sentry.Environment)
			
			// Add version timestamp for cache busting
			version := fmt.Sprintf("%d", time.Now().Unix())
			html = strings.ReplaceAll(html, "alpinejs@3.x.x/dist/cdn.min.js", "alpinejs@3.x.x/dist/cdn.min.js?v="+version)
			html = strings.ReplaceAll(html, "{{VERSION}}", version)
			
			// Set content type and cache headers
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private, max-age=0")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			w.Header().Set("X-Accel-Expires", "0") // For nginx
			w.Header().Set("Surrogate-Control", "no-store") // For CDN/frontdoor
			w.Header().Set("Vary", "*") // Prevent caching based on any header
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(html))
			return
		}
		
		// For non-HTML files, add cache headers for JS/CSS files
		if strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// validateCredentials checks S3 credentials
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

// getFeatures lists enabled modules
func (s *Server) getFeatures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	features := map[string]interface{}{
		"virustotal": map[string]interface{}{
			"enabled":      s.config.VirusTotal.Enabled,
			"scanUploads":  s.config.VirusTotal.ScanUploads,
			"blockThreats": s.config.VirusTotal.BlockThreats,
			"maxFileSize":  s.config.VirusTotal.MaxFileSize,
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
		// Fast path: skip logging for health and readiness checks  
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware is no longer used - auth is handled inline in setupRoutes
//
//nolint:unused
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health and readiness checks
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}

		// Fast path: inline authentication check
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

// isPublicPath checks if path requires no authentication
func (s *Server) isPublicPath(requestPath string) bool {
	// Normalize path to prevent traversal attacks like /../, /./, //
	cleanPath := path.Clean(requestPath)
	
	// Ensure the cleaned path starts with / to prevent relative path attacks
	if !strings.HasPrefix(cleanPath, "/") {
		return false
	}
	
	// Exact matches for monitoring endpoints (security-critical)
	exactPaths := []string{"/health", "/ready", "/metrics", "/stats"}
	for _, exactPath := range exactPaths {
		if cleanPath == exactPath {
			return true
		}
	}
	
	// Prefix matches with strict validation to prevent traversal
	publicPrefixes := []string{"/docs/", "/api/auth/"}
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(cleanPath, prefix) {
			// Additional security: ensure no traversal beyond the prefix
			relativePath := cleanPath[len(prefix):]
			// Reject any path containing .. or other suspicious patterns
			if strings.Contains(relativePath, "..") || 
			   strings.Contains(relativePath, "//") ||
			   strings.Contains(relativePath, "\\") {
				logrus.WithFields(logrus.Fields{
					"path": requestPath,
					"cleaned_path": cleanPath,
					"relative_path": relativePath,
				}).Warn("Path traversal attempt detected")
				return false
			}
			return true
		}
	}
	
	return false
}

// extractAccessKeyFromV4Auth gets access key from v4 signature
func (s *Server) extractAccessKeyFromV4Auth(authHeader string) string {
	if authHeader == "" || !strings.Contains(authHeader, "Credential=") {
		return ""
	}

	// Find credential start position safely
	credIndex := strings.Index(authHeader, "Credential=")
	if credIndex == -1 {
		return ""
	}
	
	credStart := credIndex + 11 // len("Credential=")
	if credStart >= len(authHeader) {
		return ""
	}

	// Find end delimiter safely - look for '/' or ',' 
	remaining := authHeader[credStart:]
	credEnd := strings.Index(remaining, "/")
	if credEnd == -1 {
		credEnd = strings.Index(remaining, ",")
		if credEnd == -1 {
			return ""
		}
	}
	
	// Bounds check before slicing
	if credEnd <= 0 || credStart+credEnd > len(authHeader) {
		return ""
	}

	accessKey := authHeader[credStart : credStart+credEnd]
	
	// Additional validation: access keys should be reasonable length
	if len(accessKey) < 3 || len(accessKey) > 128 {
		logrus.WithField("key_length", len(accessKey)).Warn("Suspicious access key length")
		return ""
	}

	return accessKey
}

// authenticateWithAPIKey checks API key authentication
func (s *Server) authenticateWithAPIKey(accessKey string, r *http.Request) bool {
	// For AWS-style requests, we need to validate the signature
	// Since we don't have the secret key in the request, we need to:
	// 1. Look up the API key
	// 2. Get the secret key
	// 3. Recompute the signature and compare
	
	// For now, let's implement a simplified approach:
	// Check if this access key exists in our API key store
	if s.auth0 == nil {
		return false
	}
	
	// Get all keys and find the one with this access key
	allKeys := s.getAllAPIKeys()
	for _, key := range allKeys {
		if key.AccessKey == accessKey {
			// Found the key, validate expiration first
			if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
				logrus.WithField("access_key", accessKey).Warn("API key has expired")
				return false
			}
			
			// Critical: Validate the cryptographic signature using the secret key
			if !s.validateAPIKeySignature(r, key) {
				logrus.WithField("access_key", accessKey).Warn("API key signature validation failed")
				return false
			}
			
			// Update last used only after successful validation
			now := time.Now()
			key.LastUsed = &now
			
			logrus.WithFields(logrus.Fields{
				"user_id":    key.UserID,
				"access_key": accessKey,
				"key_name":   key.Name,
			}).Info("API key cryptographically validated")
			
			return true
		}
	}
	
	return false
}

// getAllAPIKeys retrieves stored API keys
func (s *Server) getAllAPIKeys() []*APIKey {
	if s.auth0 == nil || s.auth0.apiKeyStore == nil {
		return nil
	}
	
	s.auth0.apiKeyStore.mu.RLock()
	defer s.auth0.apiKeyStore.mu.RUnlock()
	
	var keys []*APIKey
	for _, key := range s.auth0.apiKeyStore.keys {
		keys = append(keys, key)
	}
	
	return keys
}

// validateSecureSession verifies Auth0 session security
func (s *Server) validateSecureSession(session interface{}) bool {
	// Type assertion to access session values
	type sessionInterface interface {
		Values() map[interface{}]interface{}
	}
	
	sess, ok := session.(sessionInterface)
	if !ok {
		return false
	}
	
	values := sess.Values()
	
	// Check authentication flag
	authenticated, ok := values["authenticated"].(bool)
	if !ok || !authenticated {
		return false
	}
	
	// Check session expiration (critical security check)
	if expiresAt, ok := values["expires_at"].(time.Time); ok {
		if time.Now().After(expiresAt) {
			return false
		}
	} else {
		// No expiration set - reject for security
		return false
	}
	
	// Validate session integrity using constant-time comparison
	if expectedHash, ok := values["integrity_hash"].(string); ok {
		if userSub, ok := values["user_sub"].(string); ok {
			// Recompute integrity hash
			computedHash := s.computeSessionIntegrityHash(userSub, values["expires_at"].(time.Time))
			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(computedHash)) != 1 {
				return false
			}
		} else {
			return false
		}
	} else {
		// No integrity hash - reject for security
		return false
	}
	
	return true
}

// checkAuth0Session verifies Auth0 session
func (s *Server) checkAuth0Session(r *http.Request) bool {
	if !s.config.Auth0.Enabled || s.auth0 == nil {
		return false
	}
	
	session, err := s.auth0.store.Get(r, sessionName)
	if err != nil {
		return false
	}
	
	if s.validateSecureSession(session) {
		logrus.WithField("user_sub", session.Values["user_sub"]).Debug("Authenticated via Auth0 session, bypassing S3 auth")
		return true
	}
	
	logrus.WithField("session_id", session.ID).Warn("Session validation failed - expired or tampered")
	return false
}

// cleanMinIOClientHeaders fixes mc client auth headers
func (s *Server) cleanMinIOClientHeaders(r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	if !strings.Contains(strings.ToLower(userAgent), "minio") && !strings.Contains(strings.ToLower(userAgent), "mc") {
		return
	}
	
	authHeader := r.Header.Get("Authorization")
	if strings.Contains(authHeader, "\n") || strings.Contains(authHeader, "\r") {
		cleanedHeader := strings.ReplaceAll(authHeader, "\n", "")
		cleanedHeader = strings.ReplaceAll(cleanedHeader, "\r", "")
		r.Header.Set("Authorization", cleanedHeader)
	}
}

// tryAPIKeyAuth checks multiple API key formats
func (s *Server) tryAPIKeyAuth(r *http.Request) bool {
	if !s.config.Auth0.Enabled || s.auth0 == nil {
		return false
	}
	
	authHeader := r.Header.Get("Authorization")
	
	// Try AWS Signature Version 4 with API keys
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		if accessKey := s.extractAccessKeyFromV4Auth(authHeader); accessKey != "" {
			if strings.HasPrefix(accessKey, "fse_") {
				if s.authenticateWithAPIKey(accessKey, r) {
					logrus.WithField("access_key", accessKey).Info("API key AWS v4 authentication successful")
					return true
				}
			}
		}
	} else if strings.HasPrefix(authHeader, "AWS ") {
		// Try AWS Signature Version 2 with API keys
		parts := strings.SplitN(authHeader[4:], ":", 2)
		if len(parts) == 2 {
			accessKey := parts[0]
			if strings.HasPrefix(accessKey, "fse_") {
				if s.authenticateWithAPIKey(accessKey, r) {
					logrus.WithField("access_key", accessKey).Info("API key AWS v2 authentication successful")
					return true
				}
			}
		}
	} else if strings.HasPrefix(authHeader, "Bearer ") {
		// Support Bearer token format for API keys: "Bearer access_key:secret_key"
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if strings.Contains(token, ":") {
			parts := strings.SplitN(token, ":", 2)
			if len(parts) == 2 {
				accessKey := parts[0]
				secretKey := parts[1]
				
				if apiKey, err := s.auth0.ValidateAPIKey(accessKey, secretKey); err == nil {
					logrus.WithFields(logrus.Fields{
						"user_id":    apiKey.UserID,
						"access_key": accessKey,
						"key_name":   apiKey.Name,
					}).Info("API key Bearer authentication successful")
					return true
				}
			}
		}
	}
	
	return false
}

// computeSessionIntegrityHash generates session integrity hash
func (s *Server) computeSessionIntegrityHash(userSub string, expiresAt time.Time) string {
	// Use server secret (Auth0 client secret) as HMAC key
	key := s.config.Auth0.ClientSecret
	if key == "" {
		// Fallback to a server-specific secret (in production, use proper key management)
		key = "fallback-integrity-key-change-in-production"
	}
	
	// Create integrity hash from user ID and expiration
	hmacHash := hmac.New(sha256.New, []byte(key))
	hmacHash.Write([]byte(userSub))
	hmacHash.Write([]byte(expiresAt.Format(time.RFC3339)))
	return hex.EncodeToString(hmacHash.Sum(nil))
}

// validateAPIKeySignature verifies API key signature
func (s *Server) validateAPIKeySignature(r *http.Request, apiKey *APIKey) bool {
	authHeader := r.Header.Get("Authorization")
	
	// Handle AWS Signature Version 4
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return s.validateAWSV4SignatureWithAPIKey(r, apiKey, authHeader)
	}
	
	// Handle AWS Signature Version 2  
	if strings.HasPrefix(authHeader, "AWS ") {
		return s.validateAWSV2SignatureWithAPIKey(r, apiKey, authHeader)
	}
	
	return false
}

// validateAWSV4SignatureWithAPIKey verifies v4 signature with API key
func (s *Server) validateAWSV4SignatureWithAPIKey(r *http.Request, apiKey *APIKey, authHeader string) bool {
	// Parse authorization header components
	parts := strings.Split(authHeader[17:], ", ")
	authComponents := make(map[string]string)
	
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			authComponents[kv[0]] = kv[1]
		}
	}
	
	signature := authComponents["Signature"]
	if signature == "" {
		return false
	}
	
	// Extract credential components
	credential := authComponents["Credential"]
	credParts := strings.Split(credential, "/")
	if len(credParts) < 5 {
		return false
	}
	
	dateStr := credParts[1]
	region := credParts[2] 
	service := credParts[3]
	signedHeaders := authComponents["SignedHeaders"]
	
	// Get required headers
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return false
	}
	
	// Rebuild canonical request (same logic as AWSV4Provider)
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	
	canonicalQueryString := r.URL.Query().Encode()
	
	// Build canonical headers
	canonicalHeaders := ""
	signedHeadersList := strings.Split(signedHeaders, ";")
	for _, header := range signedHeadersList {
		value := r.Header.Get(header)
		if header == "host" {
			value = r.Host
		}
		canonicalHeaders += fmt.Sprintf("%s:%s\n", strings.ToLower(header), strings.TrimSpace(value))
	}
	
	contentHash := r.Header.Get("X-Amz-Content-Sha256")
	if contentHash == "" {
		contentHash = "UNSIGNED-PAYLOAD"
	}
	
	// Create canonical request
	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		contentHash,
	}, "\n")
	
	// Create string to sign
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		fmt.Sprintf("%s/%s/%s/aws4_request", dateStr, region, service),
		hex.EncodeToString(canonicalRequestHash[:]),
	}, "\n")
	
	// Calculate signing key using API key secret (same logic as in auth package)
	signingKey := s.getSigningKey(apiKey.SecretKey, dateStr, region, service)
	
	// Calculate expected signature
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(stringToSign))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(signature)) == 1
}

// validateAWSV2SignatureWithAPIKey verifies v2 signature with API key
func (s *Server) validateAWSV2SignatureWithAPIKey(r *http.Request, apiKey *APIKey, authHeader string) bool {
	parts := strings.SplitN(authHeader[4:], ":", 2)
	if len(parts) != 2 {
		return false
	}
	
	providedSignature := parts[1]
	
	// Build string to sign (same logic as AWSV2Provider)
	var builder strings.Builder
	builder.WriteString(r.Method)
	builder.WriteString("\n")
	builder.WriteString(r.Header.Get("Content-MD5"))
	builder.WriteString("\n")
	builder.WriteString(r.Header.Get("Content-Type"))
	builder.WriteString("\n")
	builder.WriteString(r.Header.Get("Date"))
	builder.WriteString("\n")
	
	// Add canonical headers
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "x-amz-") {
			builder.WriteString(lowerKey)
			builder.WriteString(":")
			builder.WriteString(strings.Join(values, ","))
			builder.WriteString("\n")
		}
	}
	
	// Add canonical resource
	builder.WriteString(r.URL.Path)
	if r.URL.RawQuery != "" {
		builder.WriteString("?")
		builder.WriteString(r.URL.RawQuery)
	}
	
	stringToSign := builder.String()
	
	// Calculate expected signature using API key secret
	h := hmac.New(sha256.New, []byte(apiKey.SecretKey))
	h.Write([]byte(stringToSign))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(providedSignature)) == 1
}

// getSigningKey generates AWS signature key
func (s *Server) getSigningKey(key, dateStamp, regionName, serviceName string) []byte {
	kDate := s.hmacSHA256([]byte("AWS4"+key), []byte(dateStamp))
	kRegion := s.hmacSHA256(kDate, []byte(regionName))
	kService := s.hmacSHA256(kRegion, []byte(serviceName))
	kSigning := s.hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256
func (s *Server) hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// isAdminUser checks admin privileges
func isAdminUser(roles []string) bool {
	for _, role := range roles {
		if role == "admin" || role == "storage-admin" || role == "super-admin" {
			return true
		}
	}
	return false
}

func (s *Server) serveAdminUI(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	if s.auth0 == nil || !s.auth0.IsAuthenticated(r) {
		http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
		return
	}

	// Check if user is admin
	session, _ := s.auth0.store.Get(r, sessionName)
	var isAdmin bool
	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		roles := strings.Split(rolesStr, ",")
		for _, role := range roles {
			if role == "admin" || role == "storage-admin" {
				isAdmin = true
				break
			}
		}
	}

	if !isAdmin {
		http.Error(w, "Access denied. Admin role required.", http.StatusForbidden)
		return
	}

	// Serve the admin.html file
	http.ServeFile(w, r, filepath.Join(s.config.UI.StaticPath, "admin.html"))
}

// Close releases server resources gracefully
func (s *Server) Close() error {
	// Mark server as shutting down immediately
	s.SetShuttingDown()
	
	logrus.Info("Starting graceful shutdown of proxy server resources...")
	
	var errors []error
	
	// Close database connections
	if s.db != nil {
		logrus.Info("Closing database connections...")
		if err := s.db.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close database connections")
			errors = append(errors, fmt.Errorf("database close error: %w", err))
		} else {
			logrus.Info("Database connections closed successfully")
		}
	}
	
	// Close VirusTotal scanner if it has cleanup needs
	if s.scanner != nil {
		logrus.Info("Cleaning up VirusTotal scanner...")
		// VirusTotal scanner doesn't currently have a Close method, but we log for completeness
		logrus.Info("VirusTotal scanner cleanup completed")
	}
	
	// Close Auth0 resources if enabled
	if s.auth0 != nil {
		logrus.Info("Cleaning up Auth0 resources...")
		// Auth0 handler doesn't currently have cleanup, but we prepare for it
		logrus.Info("Auth0 cleanup completed")
	}
	
	// Close storage backend if it has cleanup needs
	if s.storage != nil {
		logrus.Info("Cleaning up storage backend...")
		// Storage backends don't currently implement Close(), but we prepare for it
		logrus.Info("Storage backend cleanup completed")
	}
	
	if len(errors) > 0 {
		logrus.WithField("error_count", len(errors)).Error("Some resources failed to close gracefully")
		return fmt.Errorf("multiple close errors: %v", errors)
	}
	
	logrus.Info("Proxy server resources closed successfully")
	return nil
}
