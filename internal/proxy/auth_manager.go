package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/sirupsen/logrus"
)

// AuthContext holds authentication information for a request
type AuthContext struct {
	Authenticated bool
	UserSub       string
	UserRoles     []string
	IsAdmin       bool
	AuthMethod    string
}

// AuthenticationManager handles all authentication logic
type AuthenticationManager struct {
	config     *config.Config
	auth0      *Auth0Handler
	awsAuth    auth.Provider
	logger     *logrus.Logger
}

// NewAuthenticationManager creates a new authentication manager
func NewAuthenticationManager(cfg *config.Config, auth0Handler *Auth0Handler, awsAuth auth.Provider) *AuthenticationManager {
	logger := logrus.StandardLogger()
	if logger == nil {
		logger = logrus.New()
	}
	
	return &AuthenticationManager{
		config:  cfg,
		auth0:   auth0Handler,
		awsAuth: awsAuth,
		logger:  logger,
	}
}

// AuthenticateRequest performs authentication for incoming requests
func (am *AuthenticationManager) AuthenticateRequest(r *http.Request) (*AuthContext, error) {
	// Skip authentication if disabled
	if am.config.Auth.Type == "none" {
		return &AuthContext{
			Authenticated: true,
			AuthMethod:    "none",
		}, nil
	}

	authCtx := &AuthContext{}
	
	// Check if this is a public path
	isPublicPath := am.isPublicPath(r.URL.Path)
	isUIPath := am.isUIPath(r.URL.Path)

	am.logger.WithFields(logrus.Fields{
		"path":           r.URL.Path,
		"auth_type":      am.config.Auth.Type,
		"is_public_path": isPublicPath,
		"is_ui_path":     isUIPath,
	}).Info("Starting authentication check")

	// Public paths don't require authentication
	if isPublicPath {
		authCtx.Authenticated = true
		authCtx.AuthMethod = "public"
		return authCtx, nil
	}

	// Clean MinIO client headers if needed
	am.cleanMinIOClientHeaders(r)

	// Try Auth0 session authentication first
	if am.tryAuth0Session(r, authCtx) {
		authCtx.Authenticated = true
		authCtx.AuthMethod = "auth0_session"
		return authCtx, nil
	}

	// For UI paths, if not authenticated, return early
	// The Auth0 middleware will handle the redirect
	if isUIPath && !authCtx.Authenticated {
		if am.config.Auth0.Enabled && am.auth0 != nil {
			return authCtx, &AuthenticationError{
				Type:    "auth0_required",
				Message: "Auth0 authentication required for UI access",
				Code:    http.StatusUnauthorized,
			}
		}
	}

	// Try API key authentication
	if am.tryAPIKeyAuth(r, authCtx) {
		authCtx.Authenticated = true
		authCtx.AuthMethod = "api_key"
		return authCtx, nil
	}

	// For S3 operations (non-UI paths), try AWS signature authentication
	if !isUIPath && !authCtx.Authenticated {
		if err := am.awsAuth.Authenticate(r); err != nil {
			am.logger.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"method": r.Method,
				"error":  err.Error(),
			}).Warn("AWS signature authentication failed")
			
			return authCtx, &AuthenticationError{
				Type:    "aws_signature_failed",
				Message: "AWS signature authentication failed",
				Code:    http.StatusForbidden,
			}
		}
		authCtx.Authenticated = true
		authCtx.AuthMethod = "aws_signature"
	}

	return authCtx, nil
}

// ApplyAuthContext applies authentication context to the request
func (am *AuthenticationManager) ApplyAuthContext(r *http.Request, authCtx *AuthContext) *http.Request {
	if !authCtx.Authenticated {
		return r
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, "authenticated", true)
	ctx = context.WithValue(ctx, "auth_method", authCtx.AuthMethod)
	
	if authCtx.UserSub != "" {
		ctx = context.WithValue(ctx, "user_sub", authCtx.UserSub)
	}
	
	if len(authCtx.UserRoles) > 0 {
		ctx = context.WithValue(ctx, "user_roles", authCtx.UserRoles)
		ctx = context.WithValue(ctx, "is_admin", authCtx.IsAdmin)
	}

	return r.WithContext(ctx)
}

// CleanHeaders removes auth headers based on path type
func (am *AuthenticationManager) CleanHeaders(r *http.Request) {
	isUIPath := am.isUIPath(r.URL.Path)
	isPublicPath := am.isPublicPath(r.URL.Path)

	// Only remove auth headers for UI and public paths
	// S3 requests need to preserve auth headers for the S3 handler
	if isUIPath || isPublicPath {
		am.logger.WithFields(logrus.Fields{
			"path":    r.URL.Path,
			"hadAuth": r.Header.Get("Authorization") != "",
		}).Debug("Removing auth headers after authentication for non-S3 path")

		r.Header.Del("Authorization")
		r.Header.Del("X-Amz-Security-Token")
		r.Header.Del("X-Amz-Credential")
		r.Header.Del("X-Amz-Date")
		r.Header.Del("X-Amz-SignedHeaders")
		r.Header.Del("X-Amz-Signature")
	} else {
		am.logger.WithFields(logrus.Fields{
			"path":    r.URL.Path,
			"hadAuth": r.Header.Get("Authorization") != "",
		}).Debug("Preserving auth headers for S3 request")
	}
}

// tryAuth0Session attempts Auth0 session authentication
func (am *AuthenticationManager) tryAuth0Session(r *http.Request, authCtx *AuthContext) bool {
	if !am.config.Auth0.Enabled || am.auth0 == nil {
		return false
	}

	session, err := am.auth0.store.Get(r, sessionName)
	if err != nil {
		return false
	}

	if !am.validateSecureSession(session) {
		am.logger.WithField("session_id", session.ID).Warn("Session validation failed - expired or tampered")
		return false
	}

	// Extract user information from session
	if userSub, ok := session.Values["user_sub"].(string); ok {
		authCtx.UserSub = userSub
	}

	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		authCtx.UserRoles = strings.Split(rolesStr, ",")
		authCtx.IsAdmin = isAdminUser(authCtx.UserRoles)
	}

	am.logger.WithField("user_sub", authCtx.UserSub).Debug("Authenticated via Auth0 session")
	return true
}

// tryAPIKeyAuth attempts API key authentication
func (am *AuthenticationManager) tryAPIKeyAuth(r *http.Request, authCtx *AuthContext) bool {
	if !am.config.Auth0.Enabled || am.auth0 == nil {
		return false
	}

	authHeader := r.Header.Get("Authorization")

	// Try AWS Signature Version 4 with API keys
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		if accessKey := am.extractAccessKeyFromV4Auth(authHeader); accessKey != "" {
			if strings.HasPrefix(accessKey, "fse_") {
				if am.authenticateWithAPIKey(accessKey, r) {
					am.logger.WithField("access_key", accessKey).Info("API key AWS v4 authentication successful")
					authCtx.UserSub = accessKey // Use access key as user identifier
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
				if am.authenticateWithAPIKey(accessKey, r) {
					am.logger.WithField("access_key", accessKey).Info("API key AWS v2 authentication successful")
					authCtx.UserSub = accessKey
					return true
				}
			}
		}
	}

	return false
}

// isPublicPath checks if a path should be publicly accessible
func (am *AuthenticationManager) isPublicPath(path string) bool {
	// Reject paths with traversal attempts (security-first approach)
	if strings.Contains(path, "..") || 
	   strings.Contains(path, "//") || 
	   strings.Contains(path, "\\") ||
	   !strings.HasPrefix(path, "/") {
		return false
	}

	// Exact matches for monitoring endpoints (security-critical)
	exactPaths := []string{"/health", "/readiness", "/metrics"}
	for _, exactPath := range exactPaths {
		if path == exactPath {
			return true
		}
	}
	
	// Prefix matches with strict validation to prevent traversal
	publicPrefixes := []string{"/docs/", "/api/auth/"}
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(path, prefix) {
			// Additional security: ensure no traversal beyond the prefix
			relativePath := path[len(prefix):]
			// Reject any path containing suspicious patterns after the prefix
			if strings.Contains(relativePath, "..") || 
			   strings.Contains(relativePath, "//") ||
			   strings.Contains(relativePath, "\\") {
				return false
			}
			return true
		}
	}
	
	return false
}

// isUIPath checks if a path is for the UI
func (am *AuthenticationManager) isUIPath(path string) bool {
	return strings.HasPrefix(path, "/ui/") || path == "/ui"
}

// cleanMinIOClientHeaders fixes mc client auth headers
func (am *AuthenticationManager) cleanMinIOClientHeaders(r *http.Request) {
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

// validateSecureSession verifies Auth0 session security
func (am *AuthenticationManager) validateSecureSession(session interface{}) bool {
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
			computedHash := am.computeSessionIntegrityHash(userSub, values["expires_at"].(time.Time))
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

// extractAccessKeyFromV4Auth gets access key from v4 signature
func (am *AuthenticationManager) extractAccessKeyFromV4Auth(authHeader string) string {
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
		am.logger.WithField("key_length", len(accessKey)).Warn("Suspicious access key length")
		return ""
	}

	return accessKey
}

// authenticateWithAPIKey checks API key authentication
func (am *AuthenticationManager) authenticateWithAPIKey(accessKey string, r *http.Request) bool {
	// For AWS-style requests, we need to validate the signature
	// Since we don't have the secret key in the request, we need to:
	// 1. Look up the API key
	// 2. Get the secret key
	// 3. Recompute the signature and compare
	
	// For now, let's implement a simplified approach:
	// Check if this access key exists in our API key store
	if am.auth0 == nil {
		return false
	}
	
	// Get all keys and find the one with this access key
	allKeys := am.getAllAPIKeys()
	for _, key := range allKeys {
		if key.AccessKey == accessKey {
			// Found the key, validate expiration first
			if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
				am.logger.WithField("access_key", accessKey).Warn("API key has expired")
				return false
			}
			
			// Critical: Validate the cryptographic signature using the secret key
			if !am.validateAPIKeySignature(r, key) {
				am.logger.WithField("access_key", accessKey).Warn("API key signature validation failed")
				return false
			}
			
			// Update last used only after successful validation
			now := time.Now()
			key.LastUsed = &now
			
			am.logger.WithFields(logrus.Fields{
				"user_id":    key.UserID,
				"access_key": accessKey,
				"key_name":   key.Name,
			}).Info("API key cryptographically validated")
			
			return true
		}
	}
	
	return false
}

// computeSessionIntegrityHash generates session integrity hash
func (am *AuthenticationManager) computeSessionIntegrityHash(userSub string, expiresAt time.Time) string {
	// Use server secret (Auth0 client secret) as HMAC key
	key := am.config.Auth0.ClientSecret
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

// getAllAPIKeys retrieves stored API keys
func (am *AuthenticationManager) getAllAPIKeys() []*APIKey {
	if am.auth0 == nil || am.auth0.apiKeyStore == nil {
		return nil
	}
	
	// Access the API key store with proper locking
	am.auth0.apiKeyStore.mu.RLock()
	defer am.auth0.apiKeyStore.mu.RUnlock()
	
	var allKeys []*APIKey
	for _, key := range am.auth0.apiKeyStore.keys {
		allKeys = append(allKeys, key)
	}
	
	return allKeys
}

// validateAPIKeySignature verifies API key signature
func (am *AuthenticationManager) validateAPIKeySignature(r *http.Request, apiKey *APIKey) bool {
	authHeader := r.Header.Get("Authorization")
	
	// Handle AWS Signature Version 4
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return am.validateAWSV4SignatureWithAPIKey(r, apiKey, authHeader)
	}
	
	// Handle AWS Signature Version 2  
	if strings.HasPrefix(authHeader, "AWS ") {
		return am.validateAWSV2SignatureWithAPIKey(r, apiKey, authHeader)
	}
	
	return false
}

// Placeholder methods that need full implementation
func (am *AuthenticationManager) validateAWSV4SignatureWithAPIKey(r *http.Request, apiKey *APIKey, authHeader string) bool {
	// This would contain the full AWS V4 signature validation logic
	// For now, return false as placeholder
	return false
}

func (am *AuthenticationManager) validateAWSV2SignatureWithAPIKey(r *http.Request, apiKey *APIKey, authHeader string) bool {
	// This would contain the full AWS V2 signature validation logic
	// For now, return false as placeholder
	return false
}

// AuthenticationError represents an authentication error
type AuthenticationError struct {
	Type    string
	Message string
	Code    int
}

func (e *AuthenticationError) Error() string {
	return e.Message
}

// isAdminUser checks if user has admin role
func isAdminUser(roles []string) bool {
	adminRoles := []string{"admin", "storage-admin", "super-admin"}
	for _, userRole := range roles {
		for _, adminRole := range adminRoles {
			if userRole == adminRole {
				return true
			}
		}
	}
	return false
}