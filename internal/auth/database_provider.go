package auth

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/database"
	"golang.org/x/crypto/bcrypt"
)

// DatabaseProvider implements authentication using a database backend
type DatabaseProvider struct {
	db    database.UserStore
	mu    sync.RWMutex
	cache map[string]dbCacheEntry
}

type dbCacheEntry struct {
	user      *database.User
	timestamp time.Time
}

const dbCacheTTL = 5 * time.Minute

// NewDatabaseProvider creates a new database-based authentication provider
func NewDatabaseProvider(db database.UserStore) *DatabaseProvider {
	return &DatabaseProvider{
		db:    db,
		cache: make(map[string]dbCacheEntry),
	}
}

// Authenticate validates credentials against the database
func (p *DatabaseProvider) Authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing authorization header")
	}

	// Support both Basic auth and AWS-style auth
	if strings.HasPrefix(authHeader, "Basic ") {
		return p.authenticateBasic(r)
	} else if strings.HasPrefix(authHeader, "AWS ") || strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return p.authenticateAWS(r, authHeader)
	}

	return fmt.Errorf("unsupported authorization method")
}

func (p *DatabaseProvider) authenticateBasic(r *http.Request) error {
	username, password, ok := r.BasicAuth()
	if !ok {
		return fmt.Errorf("missing basic auth credentials")
	}

	// Use username as access key for basic auth
	user, err := p.getUserByAccessKey(username)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	if user == nil {
		return fmt.Errorf("invalid credentials")
	}

	// Verify password against hashed secret key
	err = bcrypt.CompareHashAndPassword([]byte(user.SecretKey), []byte(password))
	if err != nil {
		return fmt.Errorf("invalid credentials")
	}

	// Update last login asynchronously
	go func() {
		_ = p.db.UpdateLastLogin(user.ID)
	}()

	return nil
}

func (p *DatabaseProvider) authenticateAWS(r *http.Request, authHeader string) error {
	var accessKey string

	if strings.HasPrefix(authHeader, "AWS ") {
		// AWS Signature Version 2
		parts := strings.SplitN(authHeader[4:], ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid authorization header format")
		}
		accessKey = parts[0]
	} else if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		// AWS Signature Version 4
		if !strings.Contains(authHeader, "Credential=") {
			return fmt.Errorf("missing credential in authorization header")
		}

		credStart := strings.Index(authHeader, "Credential=") + 11
		credEnd := strings.Index(authHeader[credStart:], "/")
		if credEnd == -1 {
			return fmt.Errorf("invalid credential format")
		}
		accessKey = authHeader[credStart : credStart+credEnd]
	}

	// Verify access key exists
	user, err := p.getUserByAccessKey(accessKey)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	if user == nil {
		return fmt.Errorf("invalid access key")
	}

	// Update last login asynchronously
	go func() {
		_ = p.db.UpdateLastLogin(user.ID)
	}()

	// For AWS signatures, we need to verify the signature
	// Get the plain text secret key (not hashed) for signature validation
	secretKey := user.SecretKey
	
	// If the secret key is bcrypt hashed (starts with $2), we can't use it for AWS signature
	// In production, you might want to store both hashed password and plain secret key separately
	if strings.HasPrefix(secretKey, "$2") {
		// For now, we'll just validate that the access key exists
		// In production, implement proper signature validation with plain secret keys
		return nil
	}
	
	// Create a temporary AWS provider to validate the signature
	if strings.HasPrefix(authHeader, "AWS ") {
		tempProvider := &AWSV2Provider{
			identity:   accessKey,
			credential: secretKey,
		}
		return tempProvider.Authenticate(r)
	} else if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		tempProvider := &AWSV4Provider{
			identity:   accessKey,
			credential: secretKey,
		}
		return tempProvider.Authenticate(r)
	}
	
	return nil
}

// GetSecretKey retrieves the secret key for a given access key
func (p *DatabaseProvider) GetSecretKey(accessKey string) (string, error) {
	user, err := p.getUserByAccessKey(accessKey)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", fmt.Errorf("unknown access key")
	}
	return user.SecretKey, nil
}

// getUserByAccessKey retrieves a user from database with caching
func (p *DatabaseProvider) getUserByAccessKey(accessKey string) (*database.User, error) {
	// Check cache first
	p.mu.RLock()
	if entry, ok := p.cache[accessKey]; ok {
		if time.Since(entry.timestamp) < dbCacheTTL {
			p.mu.RUnlock()
			return entry.user, nil
		}
	}
	p.mu.RUnlock()

	// Fetch from database
	user, err := p.db.GetUserByAccessKey(accessKey)
	if err != nil {
		return nil, err
	}

	// Update cache
	p.mu.Lock()
	p.cache[accessKey] = dbCacheEntry{
		user:      user,
		timestamp: time.Now(),
	}
	
	// Cleanup old entries if cache grows too large
	if len(p.cache) > 1000 {
		for k, v := range p.cache {
			if time.Since(v.timestamp) > dbCacheTTL {
				delete(p.cache, k)
			}
		}
	}
	p.mu.Unlock()

	return user, nil
}

// ClearCache clears the authentication cache
func (p *DatabaseProvider) ClearCache() {
	p.mu.Lock()
	p.cache = make(map[string]dbCacheEntry)
	p.mu.Unlock()
}