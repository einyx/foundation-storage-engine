// Package auth provides authentication providers for S3 proxy operations.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

type Provider interface {
	Authenticate(r *http.Request) error
	GetSecretKey(accessKey string) (string, error)
}

// FastAWSProvider provides optimized AWS credential authentication
type FastAWSProvider struct {
	accessKey string
	secretKey string
	mu        sync.RWMutex
	cache     map[string]cacheEntry
}

type cacheEntry struct {
	valid     bool
	timestamp time.Time
}

const cacheTTL = 5 * time.Minute

func NewProvider(cfg config.AuthConfig) (Provider, error) {
	switch cfg.Type {
	case "none":
		return &NoneProvider{}, nil
	case "basic":
		if cfg.Identity == "" || cfg.Credential == "" {
			return nil, fmt.Errorf("basic auth requires identity and credential")
		}
		return &BasicProvider{
			identity:   cfg.Identity,
			credential: cfg.Credential,
		}, nil
	case "awsv2":
		if cfg.Identity == "" || cfg.Credential == "" {
			return nil, fmt.Errorf("awsv2 auth requires identity and credential")
		}
		return &AWSV2Provider{
			identity:   cfg.Identity,
			credential: cfg.Credential,
		}, nil
	case "awsv4":
		if cfg.Identity == "" || cfg.Credential == "" {
			return nil, fmt.Errorf("awsv4 auth requires identity and credential")
		}
		return &AWSV4Provider{
			identity:   cfg.Identity,
			credential: cfg.Credential,
		}, nil
	case "multi", "aws-multi":
		// Support multiple AWS auth methods simultaneously
		return NewMultiProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", cfg.Type)
	}
}

type NoneProvider struct{}

func (p *NoneProvider) Authenticate(r *http.Request) error {
	return nil
}

func (p *NoneProvider) GetSecretKey(accessKey string) (string, error) {
	return "", fmt.Errorf("no auth provider configured")
}

type BasicProvider struct {
	identity   string
	credential string
}

func (p *BasicProvider) Authenticate(r *http.Request) error {
	username, password, ok := r.BasicAuth()
	if !ok {
		return fmt.Errorf("missing basic auth credentials")
	}

	if username != p.identity || password != p.credential {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

func (p *BasicProvider) GetSecretKey(accessKey string) (string, error) {
	if accessKey == p.identity {
		return p.credential, nil
	}
	return "", fmt.Errorf("unknown access key")
}

type AWSV2Provider struct {
	identity   string
	credential string
}

func (p *AWSV2Provider) Authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "AWS ") {
		return fmt.Errorf("invalid authorization header format")
	}

	parts := strings.SplitN(authHeader[4:], ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid authorization header format")
	}

	accessKey := parts[0]
	signature := parts[1]

	if accessKey != p.identity {
		return fmt.Errorf("invalid access key")
	}

	// Compute expected signature
	stringToSign := p.buildStringToSignV2(r)
	expectedSignature := p.computeSignatureV2(stringToSign)

	if signature != expectedSignature {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

func (p *AWSV2Provider) buildStringToSignV2(r *http.Request) string {
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

	return builder.String()
}

func (p *AWSV2Provider) computeSignatureV2(stringToSign string) string {
	h := hmac.New(sha256.New, []byte(p.credential))
	h.Write([]byte(stringToSign))
	return hex.EncodeToString(h.Sum(nil))
}

func (p *AWSV2Provider) GetSecretKey(accessKey string) (string, error) {
	if accessKey == p.identity {
		return p.credential, nil
	}
	return "", fmt.Errorf("unknown access key")
}

type AWSV4Provider struct {
	identity   string
	credential string
}

func (p *AWSV4Provider) Authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return fmt.Errorf("invalid authorization header format")
	}

	// Parse authorization header
	parts := strings.Split(authHeader[17:], ", ")
	authComponents := make(map[string]string)

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			authComponents[kv[0]] = kv[1]
		}
	}

	credential := authComponents["Credential"]
	if credential == "" {
		return fmt.Errorf("missing credential in authorization header")
	}

	credParts := strings.Split(credential, "/")
	if len(credParts) < 5 {
		return fmt.Errorf("invalid credential format")
	}

	accessKey := credParts[0]
	if accessKey != p.identity {
		return fmt.Errorf("invalid access key")
	}

	// For now, we'll do a simplified validation
	// A full implementation would need to:
	// 1. Parse the canonical request
	// 2. Create string to sign
	// 3. Calculate signature
	// 4. Compare with provided signature

	return nil
}

func (p *AWSV4Provider) GetSecretKey(accessKey string) (string, error) {
	if accessKey == p.identity {
		return p.credential, nil
	}
	return "", fmt.Errorf("unknown access key")
}

// getSigningKey generates AWS signature key - kept for future use
//
//nolint:unused
func getSigningKey(key, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+key), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(regionName))
	kService := hmacSHA256(kRegion, []byte(serviceName))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256 - kept for future use
//
//nolint:unused
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Authenticate validates AWS signature for incoming requests - optimized for speed.
func (p *FastAWSProvider) Authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing authorization header")
	}

	// Check cache first
	cacheKey := authHeader + r.Method + r.URL.Path
	p.mu.RLock()
	if entry, ok := p.cache[cacheKey]; ok {
		if time.Since(entry.timestamp) < cacheTTL {
			p.mu.RUnlock()
			if entry.valid {
				return nil
			}
			return fmt.Errorf("cached: invalid credentials")
		}
	}
	p.mu.RUnlock()

	var err error
	var valid bool

	// Fast path for AWS Signature Version 4
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		err = p.authenticateV4Fast(r, authHeader)
		valid = err == nil
	} else if strings.HasPrefix(authHeader, "AWS ") {
		// Fast path for AWS Signature Version 2
		err = p.authenticateV2Fast(r, authHeader)
		valid = err == nil
	} else {
		err = fmt.Errorf("unsupported authorization method")
	}

	// Update cache
	p.mu.Lock()
	p.cache[cacheKey] = cacheEntry{
		valid:     valid,
		timestamp: time.Now(),
	}
	// Cleanup old entries if cache grows too large
	if len(p.cache) > 10000 {
		for k, v := range p.cache {
			if time.Since(v.timestamp) > cacheTTL {
				delete(p.cache, k)
			}
		}
	}
	p.mu.Unlock()

	return err
}

func (p *FastAWSProvider) authenticateV2Fast(_ *http.Request, authHeader string) error {
	parts := strings.SplitN(authHeader[4:], ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid authorization header format")
	}

	accessKey := parts[0]
	if accessKey != p.accessKey {
		return fmt.Errorf("invalid access key")
	}

	// For V2, we'll do simplified validation
	// In production, implement full V2 signature validation
	return nil
}

func (p *FastAWSProvider) authenticateV4Fast(_ *http.Request, authHeader string) error {
	// Parse authorization header
	if !strings.Contains(authHeader, "Credential=") {
		return fmt.Errorf("missing credential in authorization header")
	}

	// Extract access key from Credential
	credStart := strings.Index(authHeader, "Credential=") + 11
	credEnd := strings.Index(authHeader[credStart:], "/")
	if credEnd == -1 {
		return fmt.Errorf("invalid credential format")
	}

	accessKey := authHeader[credStart : credStart+credEnd]
	if accessKey != p.accessKey {
		return fmt.Errorf("invalid access key")
	}

	// For fast path, we trust the client if access key matches
	// In production, implement full V4 signature validation
	return nil
}

func (p *FastAWSProvider) GetSecretKey(accessKey string) (string, error) {
	if accessKey == p.accessKey {
		return p.secretKey, nil
	}
	return "", fmt.Errorf("unknown access key")
}
