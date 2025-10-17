package s3

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/einyx/foundation-storage-engine/internal/security"
)

const (
	// S3 Limits
	maxBucketNameLength = 63
	minBucketNameLength = 3
	maxObjectKeyLength  = 1024
	maxMetadataSize     = 2048 // 2KB total metadata
	maxMetadataKeyLen   = 128
	maxMetadataValueLen = 256
	maxObjectsPerDelete = 1000
	maxListKeys         = 1000
	maxPartNumber       = 10000
	minPartSize         = 5 * 1024 * 1024               // 5MB
	maxObjectSize       = 5 * 1024 * 1024 * 1024 * 1024 // 5TB
	maxQueryParamLen    = 512
	maxContinuationLen  = 1024
)

var (
	// S3 bucket name pattern: lowercase letters, numbers, hyphens
	bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]*[a-z0-9]$`)

	// IP address pattern to reject bucket names that look like IP addresses
	ipAddressPattern = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

	// Invalid sequences for object keys
	pathTraversalPattern = regexp.MustCompile(`(\.\.\/|\.\.\\|\.\.\x00)`)

	// Metadata key pattern
	metadataKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_.]+$`)
)

// ValidationError represents an input validation error
type ValidationError struct {
	Field   string
	Value   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for %s: %s (value: %s)", e.Field, e.Message, e.Value)
}

// ValidateBucketName validates S3 bucket naming rules
func ValidateBucketName(bucket string) error {
	// First apply security validation
	if err := security.ValidateBucketName(bucket); err != nil {
		return &ValidationError{Field: "bucket", Value: bucket, Message: err.Error()}
	}

	// Length validation
	if len(bucket) < minBucketNameLength || len(bucket) > maxBucketNameLength {
		return &ValidationError{
			Field:   "bucket",
			Value:   bucket,
			Message: fmt.Sprintf("bucket name must be between %d and %d characters", minBucketNameLength, maxBucketNameLength),
		}
	}

	// Check for consecutive dots or hyphens first
	if strings.Contains(bucket, "--") || strings.Contains(bucket, "..") {
		return &ValidationError{Field: "bucket", Value: bucket, Message: "bucket name cannot contain consecutive hyphens or dots"}
	}

	// Reject IP address format
	if ipAddressPattern.MatchString(bucket) {
		return &ValidationError{Field: "bucket", Value: bucket, Message: "bucket name cannot be an IP address"}
	}

	// Character and format validation
	if !bucketNamePattern.MatchString(bucket) {
		return &ValidationError{Field: "bucket", Value: bucket, Message: "bucket name must contain only lowercase letters, numbers, and hyphens"}
	}

	// Must start and end with alphanumeric
	if !unicode.IsLetter(rune(bucket[0])) && !unicode.IsDigit(rune(bucket[0])) {
		return &ValidationError{Field: "bucket", Value: bucket, Message: "bucket name must start with a letter or number"}
	}

	lastChar := rune(bucket[len(bucket)-1])
	if !unicode.IsLetter(lastChar) && !unicode.IsDigit(lastChar) {
		return &ValidationError{Field: "bucket", Value: bucket, Message: "bucket name must end with a letter or number"}
	}

	return nil
}

// ValidateObjectKey validates object key for security and S3 compliance
func ValidateObjectKey(key string) error {
	// First apply security validation
	if err := security.ValidateObjectKey(key); err != nil {
		return &ValidationError{Field: "key", Value: key, Message: err.Error()}
	}

	// Length validation
	if len(key) > maxObjectKeyLength {
		return &ValidationError{
			Field:   "key",
			Value:   key,
			Message: fmt.Sprintf("object key cannot exceed %d bytes", maxObjectKeyLength),
		}
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(key) {
		return &ValidationError{Field: "key", Value: key, Message: "object key contains invalid UTF-8 encoding"}
	}

	return nil
}

// ValidateMetadata validates user metadata headers
func ValidateMetadata(metadata map[string]string) error {
	if metadata == nil {
		return nil
	}

	totalSize := 0

	for key, value := range metadata {
		// Validate key format
		if !metadataKeyPattern.MatchString(key) {
			return &ValidationError{
				Field:   "metadata_key",
				Value:   key,
				Message: "metadata key can only contain letters, numbers, hyphens, underscores, and dots",
			}
		}

		// Validate key length
		if len(key) > maxMetadataKeyLen {
			return &ValidationError{
				Field:   "metadata_key",
				Value:   key,
				Message: fmt.Sprintf("metadata key cannot exceed %d characters", maxMetadataKeyLen),
			}
		}

		// Validate value length
		if len(value) > maxMetadataValueLen {
			return &ValidationError{
				Field:   "metadata_value",
				Value:   value,
				Message: fmt.Sprintf("metadata value cannot exceed %d characters", maxMetadataValueLen),
			}
		}

		// Check for control characters in value
		for i, r := range value {
			if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, LF, CR
				return &ValidationError{
					Field:   "metadata_value",
					Value:   value,
					Message: fmt.Sprintf("metadata value contains invalid control character at position %d", i),
				}
			}
		}

		// Validate UTF-8 encoding
		if !utf8.ValidString(value) {
			return &ValidationError{Field: "metadata_value", Value: value, Message: "metadata value contains invalid UTF-8 encoding"}
		}

		totalSize += len(key) + len(value)
	}

	// Check total metadata size
	if totalSize > maxMetadataSize {
		return &ValidationError{
			Field:   "metadata",
			Value:   fmt.Sprintf("%d bytes", totalSize),
			Message: fmt.Sprintf("total metadata size cannot exceed %d bytes", maxMetadataSize),
		}
	}

	return nil
}

// ValidatePartNumber validates multipart upload part number
func ValidatePartNumber(partNumberStr string) (int, error) {
	if partNumberStr == "" {
		return 0, &ValidationError{Field: "partNumber", Value: partNumberStr, Message: "part number is required"}
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil {
		return 0, &ValidationError{Field: "partNumber", Value: partNumberStr, Message: "part number must be a valid integer"}
	}

	if partNumber < 1 || partNumber > maxPartNumber {
		return 0, &ValidationError{
			Field:   "partNumber",
			Value:   partNumberStr,
			Message: fmt.Sprintf("part number must be between 1 and %d", maxPartNumber),
		}
	}

	return partNumber, nil
}

// ValidateUploadID validates multipart upload ID format
func ValidateUploadID(uploadID string) error {
	if uploadID == "" {
		return &ValidationError{Field: "uploadId", Value: uploadID, Message: "upload ID cannot be empty"}
	}

	// Basic length check (upload IDs are typically 64+ characters)
	if len(uploadID) < 16 || len(uploadID) > 1024 {
		return &ValidationError{Field: "uploadId", Value: uploadID, Message: "upload ID has invalid length"}
	}

	// Check for valid characters (base64 URL-safe + some extras used by S3)
	for _, r := range uploadID {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '~') {
			return &ValidationError{Field: "uploadId", Value: uploadID, Message: "upload ID contains invalid characters"}
		}
	}

	return nil
}

// ValidateMaxKeys validates the max-keys query parameter
func ValidateMaxKeys(maxKeysStr string) (int, error) {
	if maxKeysStr == "" {
		return 1000, nil // Default value
	}

	maxKeys, err := strconv.Atoi(maxKeysStr)
	if err != nil {
		return 0, &ValidationError{Field: "max-keys", Value: maxKeysStr, Message: "max-keys must be a valid integer"}
	}

	if maxKeys < 0 {
		return 0, &ValidationError{Field: "max-keys", Value: maxKeysStr, Message: "max-keys cannot be negative"}
	}

	if maxKeys > maxListKeys {
		return maxListKeys, nil // Cap at maximum allowed
	}

	return maxKeys, nil
}

// ValidateQueryParameter validates generic query parameters for length and content
func ValidateQueryParameter(name, value string) error {
	if len(value) > maxQueryParamLen {
		return &ValidationError{
			Field:   name,
			Value:   value,
			Message: fmt.Sprintf("query parameter cannot exceed %d characters", maxQueryParamLen),
		}
	}

	// Check for control characters
	for i, r := range value {
		if r < 32 && r != 9 && r != 10 && r != 13 {
			return &ValidationError{
				Field:   name,
				Value:   value,
				Message: fmt.Sprintf("query parameter contains invalid control character at position %d", i),
			}
		}
	}

	return nil
}

// ValidateContinuationToken validates continuation token format
func ValidateContinuationToken(token string) error {
	if token == "" {
		return nil // Empty is valid
	}

	if len(token) > maxContinuationLen {
		return &ValidationError{
			Field:   "continuation-token",
			Value:   token,
			Message: fmt.Sprintf("continuation token cannot exceed %d characters", maxContinuationLen),
		}
	}

	// Validate base64-like format
	for _, r := range token {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' || r == '-' || r == '_') {
			return &ValidationError{Field: "continuation-token", Value: token, Message: "continuation token contains invalid characters"}
		}
	}

	return nil
}

// ValidateCopySource validates the x-amz-copy-source header
func ValidateCopySource(copySource string) (bucket, key string, err error) {
	if copySource == "" {
		return "", "", &ValidationError{Field: "x-amz-copy-source", Value: copySource, Message: "copy source cannot be empty"}
	}

	// URL decode the copy source
	decoded, err := url.QueryUnescape(copySource)
	if err != nil {
		return "", "", &ValidationError{Field: "x-amz-copy-source", Value: copySource, Message: "invalid URL encoding in copy source"}
	}

	// Remove leading slash if present
	source := strings.TrimPrefix(decoded, "/")

	// Split into bucket and key
	parts := strings.SplitN(source, "/", 2)
	if len(parts) != 2 {
		return "", "", &ValidationError{Field: "x-amz-copy-source", Value: copySource, Message: "copy source must be in format bucket/key"}
	}

	sourceBucket, sourceKey := parts[0], parts[1]

	// Validate source bucket name
	if err := ValidateBucketName(sourceBucket); err != nil {
		return "", "", fmt.Errorf("invalid source bucket: %w", err)
	}

	// Validate source object key
	if err := ValidateObjectKey(sourceKey); err != nil {
		return "", "", fmt.Errorf("invalid source key: %w", err)
	}

	return sourceBucket, sourceKey, nil
}

// ValidateContentLength validates Content-Length header
func ValidateContentLength(contentLengthStr string) (int64, error) {
	if contentLengthStr == "" {
		return 0, nil // Not required for all operations
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		return 0, &ValidationError{Field: "Content-Length", Value: contentLengthStr, Message: "Content-Length must be a valid integer"}
	}

	if contentLength < 0 {
		return 0, &ValidationError{Field: "Content-Length", Value: contentLengthStr, Message: "Content-Length cannot be negative"}
	}

	if contentLength > maxObjectSize {
		return 0, &ValidationError{
			Field:   "Content-Length",
			Value:   contentLengthStr,
			Message: fmt.Sprintf("Content-Length cannot exceed %d bytes", maxObjectSize),
		}
	}

	return contentLength, nil
}

// ValidateDeleteObjects validates bulk delete request
func ValidateDeleteObjects(objectKeys []string) error {
	if len(objectKeys) == 0 {
		return &ValidationError{Field: "objects", Value: "empty", Message: "delete request must contain at least one object"}
	}

	if len(objectKeys) > maxObjectsPerDelete {
		return &ValidationError{
			Field:   "objects",
			Value:   fmt.Sprintf("%d objects", len(objectKeys)),
			Message: fmt.Sprintf("cannot delete more than %d objects in a single request", maxObjectsPerDelete),
		}
	}

	// Validate each object key
	for i, key := range objectKeys {
		if err := ValidateObjectKey(key); err != nil {
			return fmt.Errorf("invalid object key at index %d: %w", i, err)
		}
	}

	return nil
}
