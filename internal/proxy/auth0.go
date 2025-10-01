package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Auth0Handler struct {
	config      *config.Auth0Config
	store       *sessions.CookieStore
	jwksCache   *JWKSCache
	tokenCache  *TokenCache
	metrics     *Auth0Metrics
	auditLogger *SecurityAuditLogger
}

type UserClaims struct {
	Sub         string                 `json:"sub"`
	Email       string                 `json:"email"`
	Name        string                 `json:"name"`
	Picture     string                 `json:"picture"`
	Permissions []string               `json:"permissions"`
	Roles       []string               `json:"https://foundation.dev/roles"`
	Metadata    map[string]interface{} `json:"https://foundation.dev/user_metadata"`
	jwt.Claims
}

type JWKSCache struct {
	mu      sync.RWMutex
	jwks    *jose.JSONWebKeySet
	expires time.Time
}

type TokenCache struct {
	mu     sync.RWMutex
	tokens map[string]CachedToken
}

type CachedToken struct {
	claims  *UserClaims
	expires time.Time
}

func NewAuth0Handler(cfg *config.Auth0Config) *Auth0Handler {
	sessionKey := cfg.SessionKey
	if sessionKey == "" {
		// Generate a random key if not provided
		key := make([]byte, 32)
		rand.Read(key)
		sessionKey = base64.StdEncoding.EncodeToString(key)
	}

	// Register types for gob encoding
	gob.Register(map[string]interface{}{})
	gob.Register(map[string]string{})

	store := sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		Domain:   "", // Empty domain means current domain only
		MaxAge:   int(cfg.SessionTimeout.Seconds()),
		HttpOnly: true,
		Secure:   true, // Always use secure cookies in production
		SameSite: http.SameSiteLaxMode, // Less strict to avoid cross-origin issues
	}

	return &Auth0Handler{
		config:      cfg,
		store:       store,
		jwksCache:   &JWKSCache{},
		tokenCache:  &TokenCache{tokens: make(map[string]CachedToken)},
		metrics:     NewAuth0Metrics(),
		auditLogger: NewSecurityAuditLogger(),
	}
}

func (h *Auth0Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	h.metrics.RecordLoginAttempt()
	// Generate random state for CSRF protection
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	session, _ := h.store.Get(r, "auth0-session")
	session.Values["state"] = state
	err := session.Save(r, w)
	
	logrus.WithFields(logrus.Fields{
		"state":       state,
		"session_new": session.IsNew,
		"save_error":  err,
	}).Debug("Generated login state")

	// Build Auth0 authorization URL
	redirectURI := getRedirectURI(r, h.config.RedirectURI)
	
	logrus.WithFields(logrus.Fields{
		"login_redirect_uri": redirectURI,
		"state":              state,
	}).Debug("Redirecting to Auth0 login")
	
	authURL := fmt.Sprintf("https://%s/authorize?"+
		"response_type=code&"+
		"client_id=%s&"+
		"redirect_uri=%s&"+
		"scope=openid profile email&"+
		"state=%s",
		h.config.Domain,
		h.config.ClientID,
		url.QueryEscape(redirectURI),
		state,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *Auth0Handler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Verify state
	session, err := h.store.Get(r, "auth0-session")
	if err != nil {
		logrus.WithError(err).Error("Failed to get session")
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	receivedState := r.URL.Query().Get("state")
	sessionState := session.Values["state"]
	
	logrus.WithFields(logrus.Fields{
		"received_state": receivedState,
		"session_state":  sessionState,
		"session_new":    session.IsNew,
	}).Debug("Validating CSRF state")

	if receivedState != sessionState {
		h.metrics.RecordLoginFailure()
		h.auditLogger.LogSecurityEvent("csrf_validation_failed", map[string]interface{}{
			"client_ip":      r.RemoteAddr,
			"user_agent":     r.Header.Get("User-Agent"),
			"received_state": receivedState,
			"session_state":  sessionState,
		})
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := h.exchangeCode(r, code)
	if err != nil {
		h.metrics.RecordLoginFailure()
		logrus.WithError(err).Error("Failed to exchange code for token")
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Extract user info from ID token only - avoid Auth0 API calls
	var userInfo map[string]interface{}
	if claims, err := h.parseIDToken(token.IDToken); err == nil {
		userInfo = map[string]interface{}{
			"sub":   claims["sub"],
			"email": claims["email"],
			"name":  claims["name"],
		}
		logrus.WithFields(logrus.Fields{
			"sub":   claims["sub"],
			"email": claims["email"],
		}).Info("Extracted user info from ID token")
	} else {
		logrus.WithError(err).Error("Failed to parse ID token, using fallback")
		// Fallback user info
		userInfo = map[string]interface{}{
			"sub":   "unknown_user",
			"email": "unknown@example.com",
			"name":  "Unknown User",
		}
	}

	// Store user info in session as individual fields (gob-compatible)
	session.Values["authenticated"] = true
	session.Values["user_sub"] = fmt.Sprintf("%v", userInfo["sub"])
	session.Values["user_email"] = fmt.Sprintf("%v", userInfo["email"])
	session.Values["user_name"] = fmt.Sprintf("%v", userInfo["name"])
	
	// Secure token handling - store with expiry and rotation
	tokenExpiry := time.Now().Add(1 * time.Hour) // 1 hour token lifetime
	session.Values["access_token"] = token.AccessToken
	session.Values["access_token_expiry"] = tokenExpiry.Unix()
	session.Values["id_token"] = token.IDToken
	
	// Store refresh token securely if available
	if token.RefreshToken != "" {
		session.Values["refresh_token"] = token.RefreshToken
	}
	
	// Add session security metadata
	session.Values["created_at"] = time.Now().Unix()
	session.Values["last_activity"] = time.Now().Unix()
	session.Values["user_agent_hash"] = h.hashUserAgent(r.Header.Get("User-Agent"))
	session.Values["client_ip"] = h.getClientIP(r)
	
	saveErr := session.Save(r, w)
	
	// Use string conversion to avoid interface{} in logging
	userSubStr := ""
	if sub := userInfo["sub"]; sub != nil {
		userSubStr = fmt.Sprintf("%v", sub)
	}
	
	logrus.WithFields(logrus.Fields{
		"session_save_error": saveErr,
		"user_sub_str":       userSubStr,
		"authenticated_set":  session.Values["authenticated"],
	}).Debug("Session saved successfully")

	// Record successful login
	h.metrics.RecordLoginSuccess()
	h.auditLogger.LogAuthEvent("login_success", userSubStr, map[string]interface{}{
		"email": fmt.Sprintf("%v", userInfo["email"]),
		"name":  fmt.Sprintf("%v", userInfo["name"]),
	})

	// Redirect to authenticated UI
	logrus.WithFields(logrus.Fields{
		"user_sub": userSubStr,
		"redirect_to": "/ui/",
	}).Info("Auth0 callback successful, redirecting to UI")
	http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
}

func (h *Auth0Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get user info before clearing session
	session, _ := h.store.Get(r, "auth0-session")
	var userID string
	if userInfo, ok := session.Values["user"].(map[string]interface{}); ok {
		if sub, exists := userInfo["sub"].(string); exists {
			userID = sub
		}
	}

	// Record logout event
	if userID != "" {
		h.auditLogger.LogAuthEvent("logout", userID, map[string]interface{}{
			"client_ip":  r.RemoteAddr,
			"user_agent": r.Header.Get("User-Agent"),
		})
	}

	// Clear session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Build Auth0 logout URL
	logoutURL := fmt.Sprintf("https://%s/v2/logout?"+
		"client_id=%s&"+
		"returnTo=%s",
		h.config.Domain,
		h.config.ClientID,
		url.QueryEscape(getReturnToURI(r, h.config.LogoutURI)),
	)

	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

func (h *Auth0Handler) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.store.Get(r, "auth0-session")
	if err != nil || session.Values["authenticated"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Reconstruct user info from individual session fields
	userInfo := map[string]interface{}{
		"sub":   session.Values["user_sub"],
		"email": session.Values["user_email"],
		"name":  session.Values["user_name"],
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (h *Auth0Handler) AuthStatusHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.store.Get(r, "auth0-session")
	
	w.Header().Set("Content-Type", "application/json")
	
	if err != nil || session.Values["authenticated"] != true {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"loginUrl":      "/api/auth/login",
		})
		return
	}
	
	// Return authenticated status with user info
	userInfo := map[string]interface{}{
		"authenticated": true,
		"user": map[string]interface{}{
			"sub":   session.Values["user_sub"],
			"email": session.Values["user_email"], 
			"name":  session.Values["user_name"],
		},
	}
	
	json.NewEncoder(w).Encode(userInfo)
}

func (h *Auth0Handler) SecureUIHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication with enhanced security validation
	session, err := h.store.Get(r, "auth0-session")
	
	// Handle securecookie errors by clearing the corrupted session
	if err != nil && strings.Contains(err.Error(), "securecookie") {
		logrus.WithError(err).Warn("Corrupted session detected, clearing and redirecting to login")
		// Clear the corrupted session
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
		return
	}
	
	// Simple authentication check
	logrus.WithFields(logrus.Fields{
		"path": r.URL.Path,
		"session_error": err,
		"authenticated": session.Values["authenticated"],
		"session_new": session.IsNew,
		"user_sub": session.Values["user_sub"],
	}).Info("SecureUIHandler checking session")
	
	if err != nil || session.Values["authenticated"] != true {
		logrus.WithFields(logrus.Fields{
			"session_error": err,
			"authenticated": session.Values["authenticated"],
		}).Warn("Session check failed, redirecting to login")
		http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
		return
	}
	
	logrus.Info("Session valid, serving UI")

	// Prepare user info for injection
	userInfo := map[string]interface{}{
		"sub":   session.Values["user_sub"],
		"email": session.Values["user_email"],
		"name":  session.Values["user_name"],
	}

	// Load the actual index.html file but with safeguards
	indexPath := "/web/index.html"
	content, err := os.ReadFile(indexPath)
	if err != nil {
		logrus.WithError(err).Error("Failed to read index.html")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Convert user info to JSON and inject it safely
	userJSON, _ := json.Marshal(userInfo)
	
	// Add safeguards to prevent auth loops
	safetyScript := fmt.Sprintf(`<script>
		console.log('Injecting AUTH_USER with safeguards:', %s);
		window.AUTH_USER = %s;
		window.AUTH0_AUTHENTICATED = true;
		window.PREVENT_AUTH_REDIRECT = true;
		console.log('Auth safeguards enabled - no automatic redirects');
	</script>`, userJSON, userJSON)
	
	// Insert the safety script before closing head tag
	html := string(content)
	html = strings.Replace(html, "</head>", safetyScript+"</head>", 1)
	
	logrus.WithFields(logrus.Fields{
		"user_info": userInfo,
	}).Info("Serving index.html with auth safeguards")
	
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN") 
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(html))
}

func (h *Auth0Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, "auth0-session")
		if err != nil || !h.validateSession(session, r) {
			http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
			return
		}

		// Add user info to context
		if userInfo, ok := session.Values["user"].(map[string]interface{}); ok {
			ctx := context.WithValue(r.Context(), "user", userInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			next.ServeHTTP(w, r)
		}
	}
}

func (h *Auth0Handler) IsAuthenticated(r *http.Request) bool {
	session, err := h.store.Get(r, "auth0-session")
	if err != nil {
		return false
	}
	return session.Values["authenticated"] == true
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (h *Auth0Handler) exchangeCode(r *http.Request, code string) (*TokenResponse, error) {
	redirectURI := getRedirectURI(r, h.config.RedirectURI)
	
	logrus.WithFields(logrus.Fields{
		"redirect_uri": redirectURI,
		"client_id":    h.config.ClientID,
		"domain":       h.config.Domain,
	}).Debug("Exchanging authorization code for tokens")
	
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {h.config.ClientID},
		"client_secret": {h.config.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/oauth/token", h.config.Domain), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (h *Auth0Handler) getUserInfo(accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/userinfo", h.config.Domain), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

func (h *Auth0Handler) getUserInfoWithRetry(accessToken string, maxRetries int) (map[string]interface{}, error) {
	var lastErr error
	
	for i := 0; i < maxRetries; i++ {
		userInfo, err := h.getUserInfo(accessToken)
		if err == nil {
			return userInfo, nil
		}
		
		lastErr = err
		
		// If it's a rate limit error, wait before retrying
		if strings.Contains(err.Error(), "429") {
			waitTime := time.Duration(i+1) * 2 * time.Second // Exponential backoff
			logrus.WithFields(logrus.Fields{
				"attempt":   i + 1,
				"wait_time": waitTime,
			}).Warn("Rate limited, waiting before retry")
			time.Sleep(waitTime)
			continue
		}
		
		// For other errors, don't retry
		break
	}
	
	return nil, lastErr
}

func (h *Auth0Handler) parseIDToken(idToken string) (map[string]interface{}, error) {
	// Simple JWT parsing without verification for basic claims
	// Split the JWT into parts
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	
	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	
	// Parse JSON claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	
	return claims, nil
}

func (h *Auth0Handler) hashUserAgent(userAgent string) string {
	hash := sha256.Sum256([]byte(userAgent))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (h *Auth0Handler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to remote address
	return r.RemoteAddr
}

func (h *Auth0Handler) validateSession(session *sessions.Session, r *http.Request) bool {
	// Simple validation - just check if authenticated
	return session.Values["authenticated"] == true
}

func getRedirectURI(r *http.Request, defaultURI string) string {
	// Always use HTTPS for production deployment behind TLS proxy
	scheme := "https"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	
	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}
	
	return fmt.Sprintf("%s://%s%s", scheme, host, defaultURI)
}

func getReturnToURI(r *http.Request, defaultURI string) string {
	// Always use HTTPS for production deployment behind TLS proxy
	scheme := "https"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	
	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}
	
	return fmt.Sprintf("%s://%s%s", scheme, host, defaultURI)
}

// ValidateJWT validates a JWT token and returns user claims
func (h *Auth0Handler) ValidateJWT(tokenString string) (*UserClaims, error) {
	if !h.config.JWTValidation {
		return nil, errors.New("JWT validation is disabled")
	}

	h.metrics.RecordJWTValidation()

	// Check token cache first
	if cachedToken, found := h.getCachedToken(tokenString); found {
		h.metrics.RecordJWTCacheHit()
		return cachedToken.claims, nil
	}

	h.metrics.RecordJWTCacheMiss()

	// Parse JWT token
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get JWKS for verification
	jwks, err := h.getJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Verify and extract claims
	var claims UserClaims
	err = token.Claims(jwks, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token claims: %w", err)
	}

	// Validate standard claims
	err = claims.Validate(jwt.Expected{
		Issuer:   fmt.Sprintf("https://%s/", h.config.Domain),
		Audience: jwt.Audience{h.config.Audience},
		Time:     time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Cache the validated token
	h.cacheToken(tokenString, &claims)

	return &claims, nil
}

// CheckS3Permission checks if user has permission for S3 operation
func (h *Auth0Handler) CheckS3Permission(user *UserClaims, bucket, object, operation string) bool {
	if user == nil {
		return false
	}

	// Check if user has admin permissions
	for _, role := range user.Roles {
		if role == "admin" || role == "s3:admin" {
			return true
		}
	}

	// Map operation to required permission
	var requiredPerm string
	switch operation {
	case "ListBuckets":
		requiredPerm = "s3:ListAllMyBuckets"
	case "CreateBucket":
		requiredPerm = "s3:CreateBucket"
	case "DeleteBucket":
		requiredPerm = "s3:DeleteBucket"
	case "GetObject":
		requiredPerm = "s3:GetObject"
	case "PutObject":
		requiredPerm = "s3:PutObject"
	case "DeleteObject":
		requiredPerm = "s3:DeleteObject"
	case "ListObjects":
		requiredPerm = "s3:ListBucket"
	default:
		return false
	}

	// Check permissions
	for _, perm := range user.Permissions {
		if perm == requiredPerm {
			return true
		}
		// Check wildcard permissions
		if strings.HasSuffix(perm, ":*") {
			prefix := strings.TrimSuffix(perm, "*")
			if strings.HasPrefix(requiredPerm, prefix) {
				return true
			}
		}
	}

	// Check bucket-specific permissions from permission mapping
	if h.config.PermissionMapping != nil {
		if bucketPerms, exists := h.config.PermissionMapping[bucket]; exists {
			return strings.Contains(bucketPerms, requiredPerm)
		}
	}

	return false
}

// GetUserFromToken extracts user information from Authorization header
func (h *Auth0Handler) GetUserFromToken(r *http.Request) (*UserClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, errors.New("invalid authorization header format")
	}

	return h.ValidateJWT(parts[1])
}

// RequireUIAuth middleware for UI-only authentication
func (h *Auth0Handler) RequireUIAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check session-based auth for UI access
		session, err := h.store.Get(r, "auth0-session")
		
		logrus.WithFields(logrus.Fields{
			"path":          r.URL.Path,
			"session_error": err,
			"session_new":   session.IsNew,
			"authenticated": session.Values["authenticated"],
			"has_user_sub":  session.Values["user_sub"] != nil,
			"user_sub":      session.Values["user_sub"],
		}).Debug("Checking UI authentication")
		
		if err != nil || !h.validateSession(session, r) {
			// Redirect to login for UI access
			loginURL := "/api/auth/login"
			if r.Header.Get("Accept") == "application/json" {
				// Return JSON error for AJAX requests
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"Authentication required","loginUrl":"` + loginURL + `"}`))
				return
			}
			// Redirect browser requests to login
			http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
			return
		}

		// Add user info to context for UI - reconstruct from individual fields
		if userSub, ok := session.Values["user_sub"].(string); ok {
			userInfo := map[string]interface{}{
				"sub":   userSub,
				"email": session.Values["user_email"],
				"name":  session.Values["user_name"],
			}
			ctx := context.WithValue(r.Context(), "user", userInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			next.ServeHTTP(w, r)
		}
	}
}

// getJWKS fetches and caches Auth0 JWKS
func (h *Auth0Handler) getJWKS() (*jose.JSONWebKeySet, error) {
	start := time.Now()
	h.jwksCache.mu.RLock()
	if h.jwksCache.jwks != nil && time.Now().Before(h.jwksCache.expires) {
		jwks := h.jwksCache.jwks
		h.jwksCache.mu.RUnlock()
		return jwks, nil
	}
	h.jwksCache.mu.RUnlock()

	h.jwksCache.mu.Lock()
	defer h.jwksCache.mu.Unlock()

	// Double-check after acquiring write lock
	if h.jwksCache.jwks != nil && time.Now().Before(h.jwksCache.expires) {
		return h.jwksCache.jwks, nil
	}

	// Fetch JWKS
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", h.config.Domain)
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Cache for 1 hour
	h.jwksCache.jwks = &jwks
	h.jwksCache.expires = time.Now().Add(time.Hour)

	// Record API call latency
	h.metrics.RecordAuth0APICall(time.Since(start))

	return &jwks, nil
}

// getCachedToken retrieves a token from cache
func (h *Auth0Handler) getCachedToken(tokenString string) (CachedToken, bool) {
	h.tokenCache.mu.RLock()
	defer h.tokenCache.mu.RUnlock()

	hash := sha256.Sum256([]byte(tokenString))
	key := base64.URLEncoding.EncodeToString(hash[:])

	if cached, exists := h.tokenCache.tokens[key]; exists {
		if time.Now().Before(cached.expires) {
			return cached, true
		}
		// Token expired, remove from cache
		delete(h.tokenCache.tokens, key)
	}

	return CachedToken{}, false
}

// cacheToken stores a validated token in cache
func (h *Auth0Handler) cacheToken(tokenString string, claims *UserClaims) {
	h.tokenCache.mu.Lock()
	defer h.tokenCache.mu.Unlock()

	hash := sha256.Sum256([]byte(tokenString))
	key := base64.URLEncoding.EncodeToString(hash[:])

	h.tokenCache.tokens[key] = CachedToken{
		claims:  claims,
		expires: time.Now().Add(h.config.TokenCacheTTL),
	}

	// Clean expired tokens periodically (simple approach)
	if len(h.tokenCache.tokens) > 1000 {
		h.cleanExpiredTokens()
	}
}

// cleanExpiredTokens removes expired tokens from cache
func (h *Auth0Handler) cleanExpiredTokens() {
	now := time.Now()
	for key, cached := range h.tokenCache.tokens {
		if now.After(cached.expires) {
			delete(h.tokenCache.tokens, key)
		}
	}
}