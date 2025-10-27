// Package s3 provides helper functions for PUT object operations.
// These functions are extracted for better testability and code organization.
package s3

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// PutRequestContext contains all relevant information about a PUT request
type PutRequestContext struct {
	Bucket           string
	Key              string
	ContentLength    int64
	ContentType      string
	TransferEncoding string
	ContentSHA256    string
	UserAgent        string
	Metadata         map[string]string
	
	// Derived properties
	IsChunkedTransfer    bool
	IsIcebergMeta        bool
	IsIcebergManifest    bool
	IsIcebergData        bool
	IsJavaClient         bool
	IsAWSCLI             bool
	ChunkedWithoutSize   bool
}

// validatePutObjectRequest performs comprehensive validation of a PUT request
// This is a pure function that doesn't modify any state
func validatePutObjectRequest(bucket, key string, r *http.Request) error {
	// Basic S3 validation
	if err := ValidateBucketName(bucket); err != nil {
		return fmt.Errorf("invalid bucket name: %w", err)
	}
	
	if err := ValidateObjectKey(key); err != nil {
		return fmt.Errorf("invalid object key: %w", err)
	}
	
	// Content-Length validation for non-chunked transfers
	if r.ContentLength < 0 && !isChunkedRequest(r) {
		return fmt.Errorf("missing Content-Length header")
	}
	
	return nil
}

// extractPutRequestContext extracts all relevant information from an HTTP request
// This is a pure function that only reads from the request
func extractPutRequestContext(bucket, key string, r *http.Request) *PutRequestContext {
	userAgent := r.Header.Get("User-Agent")
	contentSHA256 := r.Header.Get("x-amz-content-sha256")
	transferEncoding := r.Header.Get("Transfer-Encoding")
	
	ctx := &PutRequestContext{
		Bucket:           bucket,
		Key:              key,
		ContentLength:    r.ContentLength,
		ContentType:      r.Header.Get("Content-Type"),
		TransferEncoding: transferEncoding,
		ContentSHA256:    contentSHA256,
		UserAgent:        userAgent,
		Metadata:         extractRequestMetadata(r),
	}
	
	// Derive additional properties
	ctx.IsChunkedTransfer = isChunkedTransferRequest(contentSHA256, r.Header.Get("Content-Encoding"))
	ctx.IsIcebergMeta = isIcebergMetadata(key)
	ctx.IsIcebergManifest = isIcebergManifest(key)
	ctx.IsIcebergData = isIcebergData(key)
	ctx.IsJavaClient = isJavaSDKClient(userAgent)
	ctx.IsAWSCLI = isAWSCLIClient(userAgent)
	ctx.ChunkedWithoutSize = isChunkedWithoutSize(r.ContentLength, transferEncoding, contentSHA256)
	
	return ctx
}

// extractRequestMetadata extracts all relevant metadata from HTTP headers
// This is a pure function that only reads headers
func extractRequestMetadata(r *http.Request) map[string]string {
	metadata := make(map[string]string)
	
	// Extract standard metadata
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		metadata["Content-Type"] = contentType
	}
	
	if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "" {
		metadata["Content-Encoding"] = contentEncoding
	}
	
	if cacheControl := r.Header.Get("Cache-Control"); cacheControl != "" {
		metadata["Cache-Control"] = cacheControl
	}
	
	// Extract x-amz- headers
	for name, values := range r.Header {
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-amz-meta-") && len(values) > 0 {
			metadata[lowerName] = values[0]
		}
	}
	
	return metadata
}

// isChunkedRequest determines if this is a chunked transfer request
// This is a pure function with no side effects
func isChunkedRequest(r *http.Request) bool {
	return r.Header.Get("Transfer-Encoding") == "chunked" ||
		r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
}

// isChunkedTransferRequest determines if this uses AWS chunked encoding
// This is a pure function that only examines headers
func isChunkedTransferRequest(contentSHA256, contentEncoding string) bool {
	return contentSHA256 == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
		contentEncoding == "aws-chunked"
}

// calculateActualSize determines the actual size to allocate for the request
// This is a pure function that performs size calculations
func calculateActualSize(contentLength int64, decodedContentLength string) (int64, error) {
	actualSize := contentLength
	
	// Check for decoded content length header (for chunked transfers)
	if decodedContentLength != "" {
		decoded, err := strconv.ParseInt(decodedContentLength, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid decoded content length: %w", err)
		}
		if decoded > 0 {
			actualSize = decoded
		}
	}
	
	// Validate size limits
	if actualSize < 0 {
		return 0, fmt.Errorf("invalid content length: %d", actualSize)
	}
	
	// Apply reasonable limits (5GB default S3 limit)
	const maxObjectSize = 5 * 1024 * 1024 * 1024 // 5GB
	if actualSize > maxObjectSize {
		return 0, fmt.Errorf("object too large: %d bytes (max %d)", actualSize, maxObjectSize)
	}
	
	return actualSize, nil
}

// shouldUseSmallFileOptimization determines if we should use the small file path
// This is a pure function that only examines the context
func shouldUseSmallFileOptimization(ctx *PutRequestContext, actualSize int64) bool {
	const smallFileLimit = 100 * 1024 // 100KB
	
	// Use small file optimization for files under the limit
	if actualSize <= smallFileLimit {
		return true
	}
	
	// Special cases for specific file types or clients
	if ctx.IsIcebergMeta && actualSize <= 1024*1024 { // 1MB for Iceberg metadata
		return true
	}
	
	return false
}

// determineReadStrategy decides which read strategy to use based on the request context
// This is a pure function that returns a strategy enum
func determineReadStrategy(ctx *PutRequestContext, actualSize int64) ReadStrategy {
	if shouldUseSmallFileOptimization(ctx, actualSize) {
		if ctx.IsChunkedTransfer && !ctx.IsAWSCLI {
			return ReadStrategyChunkedSmall
		}
		return ReadStrategyStandardSmall
	}
	
	if ctx.IsChunkedTransfer {
		return ReadStrategyChunkedLarge
	}
	
	return ReadStrategyStandardLarge
}

// ReadStrategy represents different ways to read request bodies
type ReadStrategy int

const (
	ReadStrategyStandardSmall ReadStrategy = iota
	ReadStrategyChunkedSmall
	ReadStrategyStandardLarge
	ReadStrategyChunkedLarge
)

func (s ReadStrategy) String() string {
	switch s {
	case ReadStrategyStandardSmall:
		return "standard_small"
	case ReadStrategyChunkedSmall:
		return "chunked_small"
	case ReadStrategyStandardLarge:
		return "standard_large"
	case ReadStrategyChunkedLarge:
		return "chunked_large"
	default:
		return "unknown"
	}
}

// sanitizeETag removes quotes and validates that the ETag contains only valid hex characters
// Returns the sanitized ETag or an error if it contains invalid characters
func sanitizeETag(etag string) (string, error) {
	if etag == "" {
		return "", fmt.Errorf("empty ETag")
	}
	
	// Remove quotes and whitespace
	cleaned := strings.Trim(strings.TrimSpace(etag), `"`)
	
	// Handle multipart ETags (contain hyphens)
	if strings.Contains(cleaned, "-") {
		// For multipart ETags like "abc123-5", validate the part before the hyphen
		parts := strings.Split(cleaned, "-")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid multipart ETag format: %s", etag)
		}
		
		// Validate that the first part is valid hex
		if !isValidHex(parts[0]) {
			return "", fmt.Errorf("invalid hex characters in ETag: %s", etag)
		}
		
		// Validate that the second part is numeric (part count)
		if _, err := strconv.Atoi(parts[1]); err != nil {
			return "", fmt.Errorf("invalid part count in multipart ETag: %s", etag)
		}
		
		return cleaned, nil
	}
	
	// For single-part ETags, validate hex
	if !isValidHex(cleaned) {
		return "", fmt.Errorf("invalid hex characters in ETag: %s", etag)
	}
	
	return cleaned, nil
}

// isValidHex checks if a string contains only valid hexadecimal characters
func isValidHex(s string) bool {
	if s == "" {
		return false
	}
	
	// Use regex to check for valid hex characters only
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	return hexPattern.MatchString(s)
}

// decodeETagForHashing safely decodes an ETag for use in hash calculations
// Returns the decoded bytes or an error if the ETag is invalid
func decodeETagForHashing(etag string) ([]byte, error) {
	sanitized, err := sanitizeETag(etag)
	if err != nil {
		return nil, err
	}
	
	// For multipart ETags, only decode the hash portion (before hyphen)
	if strings.Contains(sanitized, "-") {
		hashPart := strings.Split(sanitized, "-")[0]
		return hex.DecodeString(hashPart)
	}
	
	// For single-part ETags, decode the entire string
	return hex.DecodeString(sanitized)
}