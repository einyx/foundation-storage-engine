package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
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
	apiKeyStore *APIKeyStore
}

type UserClaims struct {
	Sub         string                 `json:"sub"`
	Email       string                 `json:"email"`
	Name        string                 `json:"name"`
	Picture     string                 `json:"picture"`
	Permissions []string               `json:"permissions"`
	Roles       []string               `json:"https://foundation.dev/roles"`
	Groups      []string               `json:"https://foundation.dev/groups"`
	Metadata    map[string]interface{} `json:"https://foundation.dev/user_metadata"`
	jwt.Claims
}

// IsAdmin checks if the user has admin role
func (u *UserClaims) IsAdmin() bool {
	for _, role := range u.Roles {
		if role == "admin" || role == "storage-admin" || role == "super-admin" {
			return true
		}
	}
	return false
}

// HasRole checks if user has a specific role
func (u *UserClaims) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
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

// APIKey represents a user-generated API key for S3 backend access
type APIKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	AccessKey   string    `json:"access_key"`
	SecretKey   string    `json:"secret_key"`
	UserID      string    `json:"user_id"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Permissions []string  `json:"permissions"`
}

// APIKeyStore manages API keys in memory (could be extended to use database)
type APIKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*APIKey // keyed by access_key
	
	// Store reference to Auth0Handler for session access
	auth0Handler *Auth0Handler
}

// APIKeyRequest represents a request to create a new API key
type APIKeyRequest struct {
	Name        string    `json:"name"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
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
		apiKeyStore: &APIKeyStore{keys: make(map[string]*APIKey)},
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
	
	// Log raw token for debugging (first 50 chars of each part)
	parts := strings.Split(token.IDToken, ".")
	if len(parts) == 3 {
		headerLen := len(parts[0])
		if headerLen > 50 {
			headerLen = 50
		}
		logrus.WithFields(logrus.Fields{
			"header_sample": parts[0][:headerLen],
			"payload_length": len(parts[1]),
		}).Info("DEBUG: Raw ID token structure")
	}
	
	if claims, err := h.parseIDToken(token.IDToken); err == nil {
		// Log all claims for debugging - log at INFO level temporarily for debugging
		logrus.WithField("all_id_token_claims", claims).Info("DEBUG: All ID token claims from Azure AD")
		
		// Check multiple possible locations for groups
		groups := claims["https://foundation.dev/groups"]
		if groups == nil {
			groups = claims["groups"] // Azure AD might put them here
		}
		if groups == nil {
			groups = claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"]
		}
		if groups == nil {
			groups = claims["_claim_names"] // Sometimes Azure AD uses indirect references
		}
		if groups == nil {
			groups = claims["groupids"] // Alternative claim name
		}
		if groups == nil {
			groups = claims["roles"] // Sometimes groups come as roles
		}
		if groups == nil {
			groups = claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]
		}
		if groups == nil {
			groups = claims["wids"] // Azure AD directory roles come as wids
		}
		
		// Check for roles separately as they might contain group info
		roles := claims["https://foundation.dev/roles"]
		if roles == nil {
			roles = claims["roles"]
		}
		if roles == nil {
			roles = claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]
		}
		
		// Special handling for wids - we want to keep them as groups AND map to roles
		if wids := claims["wids"]; wids != nil {
			logrus.WithFields(logrus.Fields{
				"wids_found": true,
				"wids_type": fmt.Sprintf("%T", wids),
				"wids_raw": wids,
			}).Info("WIDs found in token claims")
			
			// Store wids as groups if no other groups found
			if groups == nil {
				groups = wids
				logrus.Info("Using WIDs as groups since no other groups found")
			}
			
			// Also map well-known directory role IDs to friendly role names
			if widsArray, ok := wids.([]interface{}); ok {
				logrus.WithField("wids_count", len(widsArray)).Info("Processing WIDs array")
				mappedRoles := []string{}
				for _, wid := range widsArray {
					if widStr, ok := wid.(string); ok {
						logrus.WithField("wid", widStr).Info("Processing WID")
						switch widStr {
						case "62e90394-69f5-4237-9190-012177145e10": // Global Administrator
							mappedRoles = append(mappedRoles, "admin", "global-admin")
						case "e8611ab8-c189-46e8-94e1-60213ab1f814": // Privileged Role Administrator
							mappedRoles = append(mappedRoles, "admin", "privileged-role-admin")
						case "158c047a-c907-4556-b7ef-446551a6b5f7": // Cloud Application Administrator
							mappedRoles = append(mappedRoles, "admin", "cloud-app-admin")
						case "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": // Privileged Authentication Administrator
							mappedRoles = append(mappedRoles, "admin", "privileged-auth-admin")
						case "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": // Conditional Access Administrator
							mappedRoles = append(mappedRoles, "admin", "conditional-access-admin")
						default:
							logrus.WithField("wid", widStr).Info("Unknown directory role ID (will be available for mapping)")
						}
					}
				}
				if len(mappedRoles) > 0 && roles == nil {
					roles = mappedRoles
				}
			}
		} else {
			logrus.Info("No WIDs found in token claims")
		}
		
		// Also try to parse access token for groups if not in ID token
		if groups == nil && token.AccessToken != "" {
			if accessClaims, err := h.parseAccessToken(token.AccessToken); err == nil {
				// Log access token claims at INFO level for debugging
				logrus.WithField("all_access_token_claims", accessClaims).Info("DEBUG: All access token claims from Azure AD")
				
				groups = accessClaims["groups"]
				if groups == nil {
					groups = accessClaims["https://foundation.dev/groups"]
				}
				if groups == nil {
					groups = accessClaims["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"]
				}
			}
		}
		
		userInfo = map[string]interface{}{
			"sub":   claims["sub"],
			"email": claims["email"],
			"name":  claims["name"],
			"roles": roles,
			"groups": groups,
		}
		logrus.WithFields(logrus.Fields{
			"sub":   claims["sub"],
			"email": claims["email"],
			"roles": claims["https://foundation.dev/roles"],
			"groups": groups,
			"provider": claims["iss"],
		}).Info("Extracted user info from ID token")
	} else {
		logrus.WithError(err).Error("Failed to parse ID token, using fallback")
		// Fallback user info
		userInfo = map[string]interface{}{
			"sub":   "unknown_user",
			"email": "unknown@example.com",
			"name":  "Unknown User",
			"roles": []string{},
			"groups": []string{},
		}
	}

	// Store user info in session as individual fields (gob-compatible)
	session.Values["authenticated"] = true
	session.Values["user_sub"] = fmt.Sprintf("%v", userInfo["sub"])
	session.Values["user_email"] = fmt.Sprintf("%v", userInfo["email"])
	session.Values["user_name"] = fmt.Sprintf("%v", userInfo["name"])
	
	// Set session options for better compatibility
	session.Options = &sessions.Options{
		Path:     "/",
		Domain:   "", // Leave empty to use current domain
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   os.Getenv("TLS_ENABLED") == "true" || os.Getenv("BEHIND_PROXY") == "true",
		SameSite: http.SameSiteLaxMode,
	}
	
	// Store roles and groups arrays - handle null values
	if userInfo["roles"] != nil {
		if roles, ok := userInfo["roles"].([]interface{}); ok {
			roleStrs := make([]string, len(roles))
			for i, role := range roles {
				roleStrs[i] = fmt.Sprintf("%v", role)
			}
			session.Values["user_roles"] = strings.Join(roleStrs, ",")
		} else {
			session.Values["user_roles"] = ""
		}
	} else {
		session.Values["user_roles"] = ""
	}
	
	// Handle groups storage with detailed logging
	if userInfo["groups"] != nil {
		logrus.WithFields(logrus.Fields{
			"groups_raw": userInfo["groups"],
			"groups_type": fmt.Sprintf("%T", userInfo["groups"]),
		}).Info("Processing groups for session storage")
		
		if groups, ok := userInfo["groups"].([]interface{}); ok {
			groupStrs := make([]string, len(groups))
			for i, group := range groups {
				groupStrs[i] = fmt.Sprintf("%v", group)
			}
			groupsJoined := strings.Join(groupStrs, ",")
			session.Values["user_groups"] = groupsJoined
			logrus.WithFields(logrus.Fields{
				"groups_count": len(groupStrs),
				"groups_stored": groupsJoined,
			}).Info("Groups stored in session")
		} else if groupStr, ok := userInfo["groups"].(string); ok {
			// Handle case where groups might already be a string
			session.Values["user_groups"] = groupStr
			logrus.WithField("groups_string", groupStr).Info("Groups already string, stored directly")
		} else {
			logrus.WithField("groups_type", fmt.Sprintf("%T", userInfo["groups"])).Warn("Groups in unexpected format")
			session.Values["user_groups"] = ""
		}
	} else {
		logrus.Info("No groups found in userInfo")
		session.Values["user_groups"] = ""
	}
	
	// Don't store tokens in cookie - they're too large
	// We'll implement token storage separately if needed
	
	// Add minimal session security metadata
	session.Values["created_at"] = time.Now().Unix()
	session.Values["last_activity"] = time.Now().Unix()
	
	saveErr := session.Save(r, w)
	
	// Use string conversion to avoid interface{} in logging
	userSubStr := ""
	if sub := userInfo["sub"]; sub != nil {
		userSubStr = fmt.Sprintf("%v", sub)
	}
	
	// Debug cookie settings
	logrus.WithFields(logrus.Fields{
		"session_save_error": saveErr,
		"user_sub_str":       userSubStr,
		"authenticated_set":  session.Values["authenticated"],
		"session_id":         session.ID,
		"session_name":       session.Name(),
		"cookie_path":        session.Options.Path,
		"cookie_domain":      session.Options.Domain,
		"cookie_secure":      session.Options.Secure,
		"cookie_httponly":    session.Options.HttpOnly,
		"cookie_samesite":    session.Options.SameSite,
		"host":               r.Host,
		"scheme":             r.URL.Scheme,
		"tls":                r.TLS != nil,
		"x_forwarded_proto":  r.Header.Get("X-Forwarded-Proto"),
	}).Info("Session save attempt with cookie details")

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
	var roles []string
	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	}
	
	var groups []string
	if groupsStr, ok := session.Values["user_groups"].(string); ok && groupsStr != "" {
		groups = strings.Split(groupsStr, ",")
	}
	
	userInfo := map[string]interface{}{
		"sub":    session.Values["user_sub"],
		"email":  session.Values["user_email"],
		"name":   session.Values["user_name"],
		"roles":  roles,
		"groups": groups,
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
	var roles []string
	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	}
	
	var groups []string
	if groupsStr, ok := session.Values["user_groups"].(string); ok && groupsStr != "" {
		groups = strings.Split(groupsStr, ",")
	}
	
	userInfo := map[string]interface{}{
		"authenticated": true,
		"user": map[string]interface{}{
			"sub":    session.Values["user_sub"],
			"email":  session.Values["user_email"], 
			"name":   session.Values["user_name"],
			"roles":  roles,
			"groups": groups,
		},
	}
	
	json.NewEncoder(w).Encode(userInfo)
}

func (h *Auth0Handler) SecureUIHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication with enhanced security validation
	session, err := h.store.Get(r, "auth0-session")
	
	// Debug cookie headers
	cookies := r.Header.Get("Cookie")
	cookieNames := []string{}
	for _, c := range r.Cookies() {
		cookieNames = append(cookieNames, c.Name)
	}
	logrus.WithFields(logrus.Fields{
		"cookies_present": cookies != "",
		"cookie_count": len(r.Cookies()),
		"cookie_names": cookieNames,
		"session_error": err,
		"session_id": session.ID,
		"session_is_new": session.IsNew,
		"session_name": session.Name(),
		"host": r.Host,
		"path": r.URL.Path,
		"x_forwarded_proto": r.Header.Get("X-Forwarded-Proto"),
	}).Info("Session retrieval debug")
	
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
		"user_agent": r.Header.Get("User-Agent"),
		"referer": r.Header.Get("Referer"),
	}).Info("SecureUIHandler checking session")
	
	// Check if we're in a redirect loop
	referer := r.Header.Get("Referer")
	if strings.Contains(referer, "/api/auth/callback") || strings.Contains(referer, "/ui/") {
		logrus.WithField("referer", referer).Debug("Detected potential redirect loop, ensuring proper session")
	}
	
	if err != nil || session.Values["authenticated"] != true {
		logrus.WithFields(logrus.Fields{
			"session_error": err,
			"authenticated": session.Values["authenticated"],
			"will_redirect_to": "/api/auth/login",
		}).Warn("Session check failed, redirecting to login")
		http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
		return
	}
	
	logrus.Info("Session valid, serving UI")

	// Prepare user info for injection
	var roles []string
	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	}
	
	var groups []string
	if groupsStr, ok := session.Values["user_groups"].(string); ok && groupsStr != "" {
		groups = strings.Split(groupsStr, ",")
	}
	
	userInfo := map[string]interface{}{
		"sub":    session.Values["user_sub"],
		"email":  session.Values["user_email"],
		"name":   session.Values["user_name"],
		"roles":  roles,
		"groups": groups,
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

func (h *Auth0Handler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	session, err := h.store.Get(r, "auth0-session")
	
	// Handle securecookie errors by clearing the corrupted session
	if err != nil && strings.Contains(err.Error(), "securecookie") {
		logrus.WithError(err).Warn("Corrupted session detected, clearing and redirecting to login")
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
		return
	}
	
	if err != nil || session.Values["authenticated"] != true {
		http.Redirect(w, r, "/api/auth/login", http.StatusTemporaryRedirect)
		return
	}

	// Prepare user info
	var roles []string
	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	}
	
	var groups []string
	if groupsStr, ok := session.Values["user_groups"].(string); ok && groupsStr != "" {
		groups = strings.Split(groupsStr, ",")
	}
	
	userInfo := map[string]interface{}{
		"sub":    session.Values["user_sub"],
		"email":  session.Values["user_email"],
		"name":   session.Values["user_name"],
		"roles":  roles,
		"groups": groups,
	}

	// Create profile page HTML
	userJSON, _ := json.Marshal(userInfo)
	profileHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - Foundation Storage Engine</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        window.AUTH_USER = %s;
        console.log('Profile page loaded for user:', window.AUTH_USER);
    </script>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="max-w-4xl mx-auto py-8 px-4">
        <!-- Header -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex items-center justify-between">
                    <h1 class="text-2xl font-bold text-gray-900">Profile Settings</h1>
                    <a href="/ui/" class="text-blue-600 hover:text-blue-800 font-medium">← Back to Storage</a>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- User Info Card -->
            <div class="lg:col-span-1">
                <div class="bg-white rounded-lg shadow-sm border border-gray-200">
                    <div class="px-6 py-4 border-b border-gray-200">
                        <h2 class="text-lg font-semibold text-gray-900">User Information</h2>
                    </div>
                    <div class="px-6 py-4">
                        <div class="text-center mb-4">
                            <div class="w-20 h-20 bg-blue-500 rounded-full flex items-center justify-center mx-auto mb-3">
                                <span class="text-2xl font-bold text-white" id="user-initials">%s</span>
                            </div>
                            <h3 class="text-lg font-medium text-gray-900" id="user-name">%s</h3>
                            <p class="text-gray-600" id="user-email">%s</p>
                        </div>
                        
                        <div class="space-y-3 text-sm">
                            <div class="flex justify-between">
                                <span class="text-gray-500">User ID:</span>
                                <span class="text-gray-900 font-mono text-xs" id="user-sub">%s</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Auth Provider:</span>
                                <span class="text-gray-900">Auth0</span>
                            </div>
                            <div class="flex justify-between items-center">
                                <span class="text-gray-500">Account Type:</span>
                                <span id="account-type" class="font-medium">
                                    <!-- Will be populated by JavaScript -->
                                </span>
                            </div>
                        </div>
                        
                        <!-- Roles and Groups Section -->
                        <div class="mt-6">
                            <h4 class="text-sm font-medium text-gray-700 mb-3">Roles & Groups</h4>
                            <div class="space-y-3">
                                <div>
                                    <span class="text-xs text-gray-500 mb-1 block">Roles:</span>
                                    <div id="user-roles" class="flex flex-wrap gap-1">
                                        <!-- Roles will be populated by JavaScript -->
                                    </div>
                                </div>
                                <div>
                                    <span class="text-xs text-gray-500 mb-1 block">Groups:</span>
                                    <div id="user-groups" class="flex flex-wrap gap-1">
                                        <!-- Groups will be populated by JavaScript -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Settings -->
            <div class="lg:col-span-2">
                <div class="bg-white rounded-lg shadow-sm border border-gray-200">
                    <div class="px-6 py-4 border-b border-gray-200">
                        <h2 class="text-lg font-semibold text-gray-900">Settings</h2>
                    </div>
                    <div class="px-6 py-4 space-y-6">
                        <!-- Storage Preferences -->
                        <div>
                            <h3 class="text-base font-medium text-gray-900 mb-3">Storage Preferences</h3>
                            <div class="space-y-4">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <label class="text-sm font-medium text-gray-700">Default View</label>
                                        <p class="text-sm text-gray-500">Choose how files are displayed by default</p>
                                    </div>
                                    <select id="defaultView" onchange="saveSettings()" class="border border-gray-300 rounded-md px-3 py-2 text-sm">
                                        <option value="list">List View</option>
                                        <option value="grid">Grid View</option>
                                    </select>
                                </div>
                                
                                <div class="flex items-center justify-between">
                                    <div>
                                        <label class="text-sm font-medium text-gray-700">Items per Page</label>
                                        <p class="text-sm text-gray-500">Number of files to show per page</p>
                                    </div>
                                    <select id="itemsPerPage" onchange="saveSettings()" class="border border-gray-300 rounded-md px-3 py-2 text-sm">
                                        <option value="25">25</option>
                                        <option value="50">50</option>
                                        <option value="100">100</option>
                                    </select>
                                </div>
                                
                                <div class="flex items-center justify-between">
                                    <div>
                                        <label class="text-sm font-medium text-gray-700">Auto-refresh</label>
                                        <p class="text-sm text-gray-500">Automatically refresh bucket contents</p>
                                    </div>
                                    <select id="autoRefresh" onchange="saveSettings()" class="border border-gray-300 rounded-md px-3 py-2 text-sm">
                                        <option value="0">Disabled</option>
                                        <option value="30">30 seconds</option>
                                        <option value="60">1 minute</option>
                                        <option value="300">5 minutes</option>
                                    </select>
                                </div>
                            </div>
                        </div>

                        <!-- API Keys Management -->
                        <div>
                            <h3 class="text-base font-medium text-gray-900 mb-3">API Keys</h3>
                            <p class="text-sm text-gray-500 mb-4">Generate keys to access the S3 backend directly from your applications. Compatible with AWS clients and SDKs.</p>
                            
                            <!-- Create API Key Form -->
                            <div class="bg-gray-50 p-4 rounded-md mb-4">
                                <h4 class="text-sm font-medium text-gray-700 mb-2">Create New API Key</h4>
                                <div class="flex gap-2">
                                    <input type="text" id="keyName" placeholder="Enter key name..." 
                                           class="flex-1 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                                    <button onclick="createAPIKey()" 
                                            class="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                        Generate
                                    </button>
                                </div>
                            </div>
                            
                            <!-- API Keys List -->
                            <div id="apiKeysList" class="space-y-3">
                                <div class="text-sm text-gray-500">Loading API keys...</div>
                            </div>
                            
                            <!-- Usage Instructions -->
                            <div class="mt-6 bg-blue-50 p-4 rounded-md">
                                <h4 class="text-sm font-medium text-blue-900 mb-2">Usage Examples</h4>
                                <div class="text-xs text-blue-800 space-y-2">
                                    <div>
                                        <strong>AWS CLI:</strong>
                                        <code class="block bg-blue-100 p-2 rounded mt-1 font-mono">
aws configure set aws_access_key_id YOUR_ACCESS_KEY<br/>
aws configure set aws_secret_access_key YOUR_SECRET_KEY<br/>
aws s3 ls --endpoint-url %s
                                        </code>
                                    </div>
                                    <div>
                                        <strong>MinIO Client (mc):</strong>
                                        <code class="block bg-blue-100 p-2 rounded mt-1 font-mono">
mc alias set storage %s YOUR_ACCESS_KEY YOUR_SECRET_KEY<br/>
mc ls storage/
                                        </code>
                                    </div>
                                    <div>
                                        <strong>Python (boto3):</strong>
                                        <code class="block bg-blue-100 p-2 rounded mt-1 font-mono">
import boto3<br/>
s3 = boto3.client('s3',<br/>
&nbsp;&nbsp;endpoint_url='%s',<br/>
&nbsp;&nbsp;aws_access_key_id='YOUR_ACCESS_KEY',<br/>
&nbsp;&nbsp;aws_secret_access_key='YOUR_SECRET_KEY')<br/>
s3.list_buckets()
                                        </code>
                                    </div>
                                    <div>
                                        <strong>curl (Bearer Token):</strong>
                                        <code class="block bg-blue-100 p-2 rounded mt-1 font-mono">
curl -H "Authorization: Bearer YOUR_ACCESS_KEY:YOUR_SECRET_KEY" \\<br/>
&nbsp;&nbsp;%s/bucket-name/
                                        </code>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Account Actions -->
                        <div>
                            <h3 class="text-base font-medium text-gray-900 mb-3">Account</h3>
                            <div class="space-y-3">
                                <button onclick="clearLocalData()" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
                                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                    </svg>
                                    Clear Local Data
                                </button>
                                
                                <a href="/api/auth/logout" class="inline-flex items-center px-4 py-2 border border-red-300 rounded-md text-sm font-medium text-red-700 bg-white hover:bg-red-50">
                                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
                                    </svg>
                                    Sign Out
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Generate initials
        function generateInitials(name) {
            if (!name) return 'U';
            const parts = name.split(' ');
            if (parts.length >= 2) {
                return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
            }
            return name.substring(0, 2).toUpperCase();
        }

        // Update initials
        if (window.AUTH_USER && window.AUTH_USER.name) {
            const initials = generateInitials(window.AUTH_USER.name);
            document.getElementById('user-initials').textContent = initials;
        }

        // Populate roles and groups
        function populateRolesAndGroups() {
            const rolesContainer = document.getElementById('user-roles');
            const groupsContainer = document.getElementById('user-groups');
            const accountTypeContainer = document.getElementById('account-type');
            
            // Check if user is admin
            let isAdmin = false;
            if (window.AUTH_USER && window.AUTH_USER.roles && Array.isArray(window.AUTH_USER.roles)) {
                const adminRoles = ['admin', 'storage-admin', 'super-admin'];
                isAdmin = window.AUTH_USER.roles.some(role => adminRoles.includes(role));
            }
            
            // Display account type
            if (isAdmin) {
                accountTypeContainer.innerHTML = '<span class="inline-block bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full font-semibold">Admin</span>';
            } else {
                accountTypeContainer.innerHTML = '<span class="inline-block bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full">Standard</span>';
            }
            
            // Populate roles
            if (window.AUTH_USER && window.AUTH_USER.roles && Array.isArray(window.AUTH_USER.roles)) {
                if (window.AUTH_USER.roles.length > 0) {
                    rolesContainer.innerHTML = window.AUTH_USER.roles.map(role => {
                        const isAdminRole = ['admin', 'storage-admin', 'super-admin'].includes(role);
                        const colorClass = isAdminRole ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800';
                        return '<span class="inline-block ' + colorClass + ' text-xs px-2 py-1 rounded-full">' + role + '</span>';
                    }).join('');
                } else {
                    rolesContainer.innerHTML = '<span class="text-xs text-gray-400">No roles assigned</span>';
                }
            } else {
                rolesContainer.innerHTML = '<span class="text-xs text-gray-400">No roles assigned</span>';
            }
            
            // Populate groups
            if (window.AUTH_USER && window.AUTH_USER.groups && Array.isArray(window.AUTH_USER.groups)) {
                if (window.AUTH_USER.groups.length > 0) {
                    groupsContainer.innerHTML = window.AUTH_USER.groups.map(group => 
                        '<span class="inline-block bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">' + group + '</span>'
                    ).join('');
                } else {
                    groupsContainer.innerHTML = '<span class="text-xs text-gray-400">No groups assigned</span>';
                }
            } else {
                groupsContainer.innerHTML = '<span class="text-xs text-gray-400">No groups assigned</span>';
            }
        }
        
        // Call the function to populate roles and groups
        populateRolesAndGroups();

        // Settings management
        function loadSettings() {
            const settings = JSON.parse(localStorage.getItem('storageEngineSettings') || '{}');
            
            // Apply defaults
            const defaults = {
                defaultView: 'list',
                itemsPerPage: '50',
                autoRefresh: '0'
            };
            
            const finalSettings = { ...defaults, ...settings };
            
            // Update form fields
            document.getElementById('defaultView').value = finalSettings.defaultView;
            document.getElementById('itemsPerPage').value = finalSettings.itemsPerPage;
            document.getElementById('autoRefresh').value = finalSettings.autoRefresh;
            
            return finalSettings;
        }
        
        function saveSettings() {
            const settings = {
                defaultView: document.getElementById('defaultView').value,
                itemsPerPage: document.getElementById('itemsPerPage').value,
                autoRefresh: document.getElementById('autoRefresh').value
            };
            
            localStorage.setItem('storageEngineSettings', JSON.stringify(settings));
            console.log('Settings saved:', settings);
            
            // Show confirmation
            const originalText = event.target.textContent;
            if (event.target.tagName === 'SELECT') {
                // Create temporary notification
                const notification = document.createElement('div');
                notification.textContent = '✓ Saved';
                notification.className = 'fixed top-4 right-4 bg-green-500 text-white px-3 py-2 rounded shadow z-50';
                document.body.appendChild(notification);
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 2000);
            }
        }
        
        // Load settings and API keys when page loads
        document.addEventListener('DOMContentLoaded', function() {
            loadSettings();
            loadAPIKeys();
        });

        // Clear local data function
        function clearLocalData() {
            if (confirm('This will clear all recent files, starred items, and preferences. Continue?')) {
                localStorage.clear();
                alert('Local data cleared successfully!');
                // Reload settings form with defaults
                setTimeout(loadSettings, 100);
            }
        }

        // API Key Management Functions
        async function loadAPIKeys() {
            try {
                const response = await fetch('/api/auth/keys');
                if (!response.ok) {
                    throw new Error('Failed to load API keys');
                }
                const data = await response.json();
                displayAPIKeys(data.keys || []);
            } catch (error) {
                console.error('Error loading API keys:', error);
                document.getElementById('apiKeysList').innerHTML = 
                    '<div class="text-sm text-red-600">Failed to load API keys</div>';
            }
        }

        async function createAPIKey() {
            const keyName = document.getElementById('keyName').value.trim();
            if (!keyName) {
                alert('Please enter a key name');
                return;
            }

            try {
                const response = await fetch('/api/auth/keys', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        name: keyName,
                        permissions: ['read:buckets', 'write:buckets']
                    })
                });

                if (!response.ok) {
                    throw new Error('Failed to create API key');
                }

                const apiKey = await response.json();
                
                // Show the newly created key in a modal/alert with copy functionality
                showNewKeyModal(apiKey);
                
                // Clear the input and reload the list
                document.getElementById('keyName').value = '';
                loadAPIKeys();
                
            } catch (error) {
                console.error('Error creating API key:', error);
                alert('Failed to create API key: ' + error.message);
            }
        }

        function showNewKeyModal(apiKey) {
            const modal = document.createElement('div');
            modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
            modal.innerHTML = 
                '<div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">' +
                    '<h3 class="text-lg font-semibold text-gray-900 mb-4">API Key Created</h3>' +
                    '<p class="text-sm text-gray-600 mb-4">Your API key has been created. Copy these credentials now - the secret key will not be shown again.</p>' +
                    '<div class="space-y-3">' +
                        '<div>' +
                            '<label class="block text-sm font-medium text-gray-700 mb-1">Access Key</label>' +
                            '<div class="flex">' +
                                '<input type="text" value="' + apiKey.access_key + '" readonly class="flex-1 border border-gray-300 rounded-l-md px-3 py-2 text-sm bg-gray-50 font-mono">' +
                                '<button onclick="copyToClipboard(\'' + apiKey.access_key + '\')" class="px-3 py-2 bg-gray-200 border border-l-0 border-gray-300 rounded-r-md text-sm hover:bg-gray-300">Copy</button>' +
                            '</div>' +
                        '</div>' +
                        '<div>' +
                            '<label class="block text-sm font-medium text-gray-700 mb-1">Secret Key</label>' +
                            '<div class="flex">' +
                                '<input type="text" value="' + apiKey.secret_key + '" readonly class="flex-1 border border-gray-300 rounded-l-md px-3 py-2 text-sm bg-gray-50 font-mono">' +
                                '<button onclick="copyToClipboard(\'' + apiKey.secret_key + '\')" class="px-3 py-2 bg-gray-200 border border-l-0 border-gray-300 rounded-r-md text-sm hover:bg-gray-300">Copy</button>' +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="mt-6 flex justify-end">' +
                        '<button onclick="closeModal(this)" class="px-4 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700">Done</button>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(modal);
        }

        function displayAPIKeys(keys) {
            const container = document.getElementById('apiKeysList');
            if (!keys || keys.length === 0) {
                container.innerHTML = '<div class="text-sm text-gray-500">No API keys found</div>';
                return;
            }

            container.innerHTML = keys.map(function(key) {
                var lastUsedHtml = key.last_used ? 
                    '<p class="text-xs text-gray-500">Last used: ' + new Date(key.last_used).toLocaleDateString() + '</p>' : 
                    '';
                
                return '<div class="border border-gray-200 rounded-md p-3">' +
                    '<div class="flex justify-between items-start">' +
                        '<div class="flex-1">' +
                            '<h4 class="text-sm font-medium text-gray-900">' + key.name + '</h4>' +
                            '<p class="text-xs text-gray-500 mt-1">Access Key: <span class="font-mono">' + key.access_key + '</span></p>' +
                            '<p class="text-xs text-gray-500">Created: ' + new Date(key.created_at).toLocaleDateString() + '</p>' +
                            lastUsedHtml +
                        '</div>' +
                        '<button onclick="revokeAPIKey(\'' + key.id + '\', \'' + key.name + '\')" ' +
                                'class="text-xs px-2 py-1 text-red-600 hover:text-red-800 border border-red-300 rounded hover:bg-red-50">' +
                            'Revoke' +
                        '</button>' +
                    '</div>' +
                '</div>';
            }).join('');
        }

        async function revokeAPIKey(keyId, keyName) {
            if (!confirm('Are you sure you want to revoke the API key "' + keyName + '"? This action cannot be undone.')) {
                return;
            }

            try {
                const response = await fetch('/api/auth/keys/revoke', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        key_id: keyId
                    })
                });

                if (!response.ok) {
                    throw new Error('Failed to revoke API key');
                }

                loadAPIKeys(); // Reload the list
                
            } catch (error) {
                console.error('Error revoking API key:', error);
                alert('Failed to revoke API key: ' + error.message);
            }
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Show temporary success message
                const notification = document.createElement('div');
                notification.textContent = '✓ Copied to clipboard';
                notification.className = 'fixed top-4 right-4 bg-green-500 text-white px-3 py-2 rounded shadow z-50';
                document.body.appendChild(notification);
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
                alert('Failed to copy to clipboard');
            });
        }

        function closeModal(button) {
            const modal = button.closest('.fixed');
            document.body.removeChild(modal);
        }
    </script>
</body>
</html>`, userJSON, 
	func() string {
		if name, ok := userInfo["name"].(string); ok && name != "" {
			parts := strings.Fields(name)
			if len(parts) >= 2 {
				return strings.ToUpper(string(parts[0][0]) + string(parts[len(parts)-1][0]))
			}
			return strings.ToUpper(name[:2])
		}
		return "U"
	}(),
	userInfo["name"], userInfo["email"], truncateUserID(fmt.Sprintf("%v", userInfo["sub"])),
	getPublicEndpoint(r), getPublicEndpoint(r), getPublicEndpoint(r), getPublicEndpoint(r))

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN") 
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(profileHTML))
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

func (h *Auth0Handler) parseAccessToken(accessToken string) (map[string]interface{}, error) {
	// Simple JWT parsing without verification for basic claims
	// Split the JWT into parts
	parts := strings.Split(accessToken, ".")
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

// truncateUserID shortens long user IDs for better UI display
func truncateUserID(userID string) string {
	if userID == "" {
		return "Unknown"
	}
	
	// For Auth0 IDs like "google-oauth2|108656223015682269080", show just the last part
	if strings.Contains(userID, "|") {
		parts := strings.Split(userID, "|")
		if len(parts) == 2 {
			// Show provider and truncated ID: "google...269080"
			provider := parts[0]
			id := parts[1]
			if len(id) > 12 {
				return fmt.Sprintf("%s...%s", provider[:6], id[len(id)-6:])
			}
			return fmt.Sprintf("%s|%s", provider, id)
		}
	}
	
	// For other long IDs, just truncate
	if len(userID) > 20 {
		return fmt.Sprintf("%s...%s", userID[:8], userID[len(userID)-8:])
	}
	
	return userID
}

// getPublicEndpoint returns the public endpoint URL for the storage engine
func getPublicEndpoint(r *http.Request) string {
	if endpoint := os.Getenv("PUBLIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	
	// Derive from request headers
	if r != nil {
		scheme := "https"
		if r.Header.Get("X-Forwarded-Proto") != "" {
			scheme = r.Header.Get("X-Forwarded-Proto")
		} else if r.TLS == nil {
			scheme = "http"
		}
		
		host := r.Host
		if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
			host = forwardedHost
		}
		
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	
	// Default fallback
	return "https://your-storage-engine.com"
}

// generateRandomString creates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateAPIKey creates a new API key for the authenticated user
func (h *Auth0Handler) GenerateAPIKey(userID string, req APIKeyRequest) (*APIKey, error) {
	// Generate secure random access and secret keys
	accessKey, err := generateRandomString(16) // 32 character hex string
	if err != nil {
		return nil, fmt.Errorf("failed to generate access key: %w", err)
	}
	
	secretKey, err := generateRandomString(32) // 64 character hex string
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret key: %w", err)
	}
	
	// Create unique ID
	keyID, err := generateRandomString(8) // 16 character hex string
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	
	// Set default permissions if none provided
	permissions := req.Permissions
	if len(permissions) == 0 {
		permissions = []string{"read:buckets", "write:buckets"}
	}
	
	apiKey := &APIKey{
		ID:          keyID,
		Name:        req.Name,
		AccessKey:   "fse_" + accessKey, // prefix to identify Foundation Storage Engine keys
		SecretKey:   secretKey,
		UserID:      userID,
		CreatedAt:   time.Now(),
		ExpiresAt:   req.ExpiresAt,
		Permissions: permissions,
	}
	
	// Store in memory
	h.apiKeyStore.mu.Lock()
	h.apiKeyStore.keys[apiKey.AccessKey] = apiKey
	h.apiKeyStore.mu.Unlock()
	
	logrus.WithFields(logrus.Fields{
		"user_id":    userID,
		"key_id":     keyID,
		"access_key": apiKey.AccessKey,
		"name":       req.Name,
	}).Info("Generated new API key")
	
	return apiKey, nil
}

// ListAPIKeys returns all API keys for a user
func (h *Auth0Handler) ListAPIKeys(userID string) []*APIKey {
	h.apiKeyStore.mu.RLock()
	defer h.apiKeyStore.mu.RUnlock()
	
	var userKeys []*APIKey
	for _, key := range h.apiKeyStore.keys {
		if key.UserID == userID {
			// Don't return the secret key in list operations
			keyClone := *key
			keyClone.SecretKey = "***hidden***"
			userKeys = append(userKeys, &keyClone)
		}
	}
	
	return userKeys
}

// RevokeAPIKey removes an API key
func (h *Auth0Handler) RevokeAPIKey(userID, keyID string) error {
	h.apiKeyStore.mu.Lock()
	defer h.apiKeyStore.mu.Unlock()
	
	// Find and remove the key
	for accessKey, key := range h.apiKeyStore.keys {
		if key.ID == keyID && key.UserID == userID {
			delete(h.apiKeyStore.keys, accessKey)
			logrus.WithFields(logrus.Fields{
				"user_id": userID,
				"key_id":  keyID,
			}).Info("Revoked API key")
			return nil
		}
	}
	
	return fmt.Errorf("API key not found or not owned by user")
}

// ValidateAPIKey checks if an API key is valid and returns the associated user
func (h *Auth0Handler) ValidateAPIKey(accessKey, secretKey string) (*APIKey, error) {
	h.apiKeyStore.mu.RLock()
	defer h.apiKeyStore.mu.RUnlock()
	
	key, exists := h.apiKeyStore.keys[accessKey]
	if !exists {
		return nil, fmt.Errorf("invalid access key")
	}
	
	if key.SecretKey != secretKey {
		return nil, fmt.Errorf("invalid secret key")
	}
	
	// Check expiration
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, fmt.Errorf("API key has expired")
	}
	
	// Update last used time
	now := time.Now()
	key.LastUsed = &now
	
	return key, nil
}

// API Handlers for key management

func (h *Auth0Handler) CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	session, err := h.store.Get(r, "auth0-session")
	if err != nil || session.Values["authenticated"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	userID, ok := session.Values["user_sub"].(string)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusBadRequest)
		return
	}
	
	// Parse request
	var req APIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Validate request
	if req.Name == "" {
		http.Error(w, "Key name is required", http.StatusBadRequest)
		return
	}
	
	// Generate the key
	apiKey, err := h.GenerateAPIKey(userID, req)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate API key")
		http.Error(w, "Failed to generate API key", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apiKey)
}

func (h *Auth0Handler) ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	session, err := h.store.Get(r, "auth0-session")
	if err != nil || session.Values["authenticated"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	userID, ok := session.Values["user_sub"].(string)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusBadRequest)
		return
	}
	
	keys := h.ListAPIKeys(userID)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}

func (h *Auth0Handler) RevokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	session, err := h.store.Get(r, "auth0-session")
	if err != nil || session.Values["authenticated"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	userID, ok := session.Values["user_sub"].(string)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusBadRequest)
		return
	}
	
	// Get key ID from URL path or request body
	var req struct {
		KeyID string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	if err := h.RevokeAPIKey(userID, req.KeyID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "API key revoked successfully",
	})
}