package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/opa"
	"github.com/sirupsen/logrus"
)

// OPAProvider wraps another auth provider and adds OPA-based authorization
type OPAProvider struct {
	opaClient    *opa.Client
	baseProvider Provider
	enabled      bool
}

// NewOPAProvider creates a new OPA auth provider that wraps a base provider
func NewOPAProvider(cfg config.AuthConfig, opaConfig config.OPAConfig, baseProvider Provider) *OPAProvider {
	var opaClient *opa.Client
	if opaConfig.Enabled {
		opaClient = opa.NewClient(opaConfig.URL, opaConfig.Timeout)
	}

	return &OPAProvider{
		opaClient:    opaClient,
		baseProvider: baseProvider,
		enabled:      opaConfig.Enabled,
	}
}

// Authenticate first validates credentials via base provider, then checks authorization via OPA
func (p *OPAProvider) Authenticate(r *http.Request) error {
	// First, authenticate using the base provider
	if err := p.baseProvider.Authenticate(r); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// If OPA is not enabled, allow access after base authentication
	if !p.enabled {
		return nil
	}

	// Extract user context and build OPA input
	input, err := p.buildOPAInput(r)
	if err != nil {
		logrus.WithError(err).Error("Failed to build OPA input")
		return fmt.Errorf("authorization context error: %w", err)
	}

	// Evaluate policy via OPA
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	allowed, err := p.opaClient.Evaluate(ctx, input)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"user":   input.User,
			"action": input.Action,
			"bucket": input.Resource.Bucket,
			"key":    input.Resource.Key,
		}).Error("OPA evaluation failed")
		return fmt.Errorf("authorization evaluation failed: %w", err)
	}

	if !allowed {
		logrus.WithFields(logrus.Fields{
			"user":   input.User,
			"action": input.Action,
			"bucket": input.Resource.Bucket,
			"key":    input.Resource.Key,
		}).Warn("Access denied by OPA policy")
		return fmt.Errorf("access denied by policy")
	}

	logrus.WithFields(logrus.Fields{
		"user":   input.User,
		"action": input.Action,
		"bucket": input.Resource.Bucket,
		"key":    input.Resource.Key,
	}).Debug("Access allowed by OPA policy")

	return nil
}

// GetSecretKey delegates to the base provider
func (p *OPAProvider) GetSecretKey(accessKey string) (string, error) {
	return p.baseProvider.GetSecretKey(accessKey)
}

// buildOPAInput constructs OPA input from the HTTP request
func (p *OPAProvider) buildOPAInput(r *http.Request) (opa.Input, error) {
	// Extract user from various auth methods
	user, err := p.extractUser(r)
	if err != nil {
		return opa.Input{}, fmt.Errorf("failed to extract user: %w", err)
	}

	// Map HTTP method to action
	action := p.mapMethodToAction(r.Method)

	// Extract bucket and key from URL path
	bucket, key := p.extractBucketAndKey(r.URL.Path)

	// Build resource context
	resource := opa.Resource{
		ID:           fmt.Sprintf("%s/%s", bucket, key),
		Organization: "default", // TODO: Extract from request context or config
		Type:         p.inferResourceType(bucket, key),
		Bucket:       bucket,
		Key:          key,
		Tags:         []string{}, // TODO: Extract from metadata if available
	}

	return opa.Input{
		User:     user,
		Action:   action,
		Resource: resource,
	}, nil
}

// extractUser extracts user identifier from the request
func (p *OPAProvider) extractUser(r *http.Request) (string, error) {
	// Check for AWS access key in Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
			// Extract access key from AWS v4 signature
			if credIndex := strings.Index(authHeader, "Credential="); credIndex != -1 {
				credStart := credIndex + 11
				if slashIndex := strings.Index(authHeader[credStart:], "/"); slashIndex != -1 {
					return authHeader[credStart : credStart+slashIndex], nil
				}
			}
		} else if strings.HasPrefix(authHeader, "AWS ") {
			// Extract access key from AWS v2 signature
			parts := strings.SplitN(authHeader[4:], ":", 2)
			if len(parts) >= 1 {
				return parts[0], nil
			}
		}
	}

	// Check for basic auth
	if username, _, ok := r.BasicAuth(); ok {
		return username, nil
	}

	// Check for session-based auth (from Auth0)
	if sessionCookie, err := r.Cookie("session"); err == nil && sessionCookie.Value != "" {
		// TODO: Decode session to extract user ID
		return "session-user", nil
	}

	// Fallback to anonymous user
	return "anonymous", nil
}

// mapMethodToAction maps HTTP methods to OPA actions
func (p *OPAProvider) mapMethodToAction(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
		return "storage:read"
	case "PUT", "POST":
		return "storage:write"
	case "DELETE":
		return "storage:delete"
	default:
		return "storage:unknown"
	}
}

// extractBucketAndKey extracts bucket and object key from URL path
func (p *OPAProvider) extractBucketAndKey(path string) (string, string) {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")
	
	// Split into components
	parts := strings.SplitN(path, "/", 2)
	
	if len(parts) == 0 {
		return "", ""
	}
	
	bucket := parts[0]
	var key string
	if len(parts) > 1 {
		key = parts[1]
	}
	
	return bucket, key
}

// inferResourceType attempts to infer the resource type based on bucket and key patterns
func (p *OPAProvider) inferResourceType(bucket, key string) string {
	// Map bucket names to resource types based on naming conventions
	bucketLower := strings.ToLower(bucket)
	
	switch {
	case strings.Contains(bucketLower, "data-product"):
		return "data-product"
	case strings.Contains(bucketLower, "data-source"):
		return "data-source"
	case strings.Contains(bucketLower, "pipeline"):
		return "pipeline"
	case strings.Contains(bucketLower, "artifact"):
		return "artifact"
	default:
		return "storage-object"
	}
}