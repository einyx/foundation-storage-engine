package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

type Auth0Handler struct {
	config *config.Auth0Config
	store  *sessions.CookieStore
}

func NewAuth0Handler(cfg *config.Auth0Config) *Auth0Handler {
	sessionKey := cfg.SessionKey
	if sessionKey == "" {
		// Generate a random key if not provided
		key := make([]byte, 32)
		rand.Read(key)
		sessionKey = base64.StdEncoding.EncodeToString(key)
	}

	return &Auth0Handler{
		config: cfg,
		store:  sessions.NewCookieStore([]byte(sessionKey)),
	}
}

func (h *Auth0Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate random state for CSRF protection
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, _ := h.store.Get(r, "auth0-session")
	session.Values["state"] = state
	session.Save(r, w)

	// Build Auth0 authorization URL
	authURL := fmt.Sprintf("https://%s/authorize?"+
		"response_type=code&"+
		"client_id=%s&"+
		"redirect_uri=%s&"+
		"scope=openid profile email&"+
		"state=%s",
		h.config.Domain,
		h.config.ClientID,
		url.QueryEscape(getRedirectURI(r, h.config.RedirectURI)),
		state,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *Auth0Handler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Verify state
	session, err := h.store.Get(r, "auth0-session")
	if err != nil {
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := h.exchangeCode(r, code)
	if err != nil {
		logrus.WithError(err).Error("Failed to exchange code for token")
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Get user info
	userInfo, err := h.getUserInfo(token.AccessToken)
	if err != nil {
		logrus.WithError(err).Error("Failed to get user info")
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Store user info in session
	session.Values["authenticated"] = true
	session.Values["user"] = userInfo
	session.Values["access_token"] = token.AccessToken
	session.Values["id_token"] = token.IDToken
	session.Save(r, w)

	// Redirect to UI
	http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
}

func (h *Auth0Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear session
	session, _ := h.store.Get(r, "auth0-session")
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

	userInfo, ok := session.Values["user"].(map[string]interface{})
	if !ok {
		http.Error(w, "User info not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (h *Auth0Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, "auth0-session")
		if err != nil || session.Values["authenticated"] != true {
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
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {h.config.ClientID},
		"client_secret": {h.config.ClientSecret},
		"code":          {code},
		"redirect_uri":  {getRedirectURI(r, h.config.RedirectURI)},
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

func getRedirectURI(r *http.Request, defaultURI string) string {
	scheme := "http"
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
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	
	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}
	
	return fmt.Sprintf("%s://%s%s", scheme, host, defaultURI)
}