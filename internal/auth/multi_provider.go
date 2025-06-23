// Package auth provides authentication providers for S3 proxy operations.
package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/meshxdata/foundation-storage-engine/internal/config"
)

// MultiProvider supports multiple authentication methods simultaneously
type MultiProvider struct {
	providers  map[string]Provider
	identity   string
	credential string
}

// NewMultiProvider creates a provider that supports multiple auth methods
func NewMultiProvider(cfg config.AuthConfig) (*MultiProvider, error) {
	if cfg.Identity == "" || cfg.Credential == "" {
		return nil, fmt.Errorf("multi auth requires identity and credential")
	}

	mp := &MultiProvider{
		providers:  make(map[string]Provider),
		identity:   cfg.Identity,
		credential: cfg.Credential,
	}

	// Initialize V2 provider
	mp.providers["awsv2"] = &AWSV2Provider{
		identity:   cfg.Identity,
		credential: cfg.Credential,
	}

	// Initialize V4 provider
	mp.providers["awsv4"] = &AWSV4Provider{
		identity:   cfg.Identity,
		credential: cfg.Credential,
	}

	// Initialize none provider for anonymous access
	mp.providers["none"] = &NoneProvider{}

	return mp, nil
}

// Authenticate tries multiple auth methods based on the request
func (p *MultiProvider) Authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")

	// Log authentication attempt
	logger := logrus.WithFields(logrus.Fields{
		"method":  r.Method,
		"path":    r.URL.Path,
		"hasAuth": authHeader != "",
	})

	// No auth header - try anonymous access
	if authHeader == "" {
		logger.Debug("No auth header, allowing anonymous access")
		return p.providers["none"].Authenticate(r)
	}

	// AWS V4 signature
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		logger.Debug("Attempting AWS V4 authentication")
		if err := p.providers["awsv4"].Authenticate(r); err != nil {
			logger.WithError(err).Debug("AWS V4 authentication failed")
			return err
		}
		logger.Debug("AWS V4 authentication successful")
		return nil
	}

	// AWS V2 signature
	if strings.HasPrefix(authHeader, "AWS ") {
		logger.Debug("Attempting AWS V2 authentication")
		if err := p.providers["awsv2"].Authenticate(r); err != nil {
			logger.WithError(err).Debug("AWS V2 authentication failed")
			return err
		}
		logger.Debug("AWS V2 authentication successful")
		return nil
	}

	// Check for x-amz headers that might indicate AWS SDK without proper auth header
	if r.Header.Get("x-amz-date") != "" || r.Header.Get("x-amz-content-sha256") != "" {
		logger.Warn("Request has AWS headers but no valid Authorization header - might be misconfigured client")
		// For now, allow it through if we're in permissive mode
		// In production, you might want to reject this
		return nil
	}

	logger.WithField("authHeader", authHeader[:20]+"...").Warn("Unknown authorization method")
	return fmt.Errorf("unsupported authorization method")
}

// GetSecretKey returns the secret key for the given access key
func (p *MultiProvider) GetSecretKey(accessKey string) (string, error) {
	if accessKey == p.identity {
		return p.credential, nil
	}
	return "", fmt.Errorf("unknown access key")
}
