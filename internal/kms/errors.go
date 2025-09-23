package kms

import (
	"errors"
	"fmt"
)

// Common KMS errors
var (
	// ErrKMSNotEnabled indicates KMS is not enabled in configuration
	ErrKMSNotEnabled = errors.New("kms encryption is not enabled")

	// ErrKeyNotFound indicates the specified KMS key was not found
	ErrKeyNotFound = errors.New("kms key not found")

	// ErrKeyDisabled indicates the KMS key is disabled
	ErrKeyDisabled = errors.New("kms key is disabled")

	// ErrInsufficientPermissions indicates missing KMS permissions
	ErrInsufficientPermissions = errors.New("insufficient kms permissions")

	// ErrInvalidKeySpec indicates an invalid key specification
	ErrInvalidKeySpec = errors.New("invalid kms key specification")

	// ErrEncryptionContextMismatch indicates encryption context doesn't match
	ErrEncryptionContextMismatch = errors.New("encryption context mismatch")
)

// KMSError wraps KMS-specific errors with additional context
type KMSError struct {
	Op        string // Operation that failed
	KeyID     string // Key ID involved
	Err       error  // Underlying error
	Retryable bool   // Whether the operation can be retried
}

// Error implements the error interface
func (e *KMSError) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("kms %s failed for key %s: %v", e.Op, e.KeyID, e.Err)
	}
	return fmt.Sprintf("kms %s failed: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error
func (e *KMSError) Unwrap() error {
	return e.Err
}

// IsRetryable returns whether the error is retryable
func (e *KMSError) IsRetryable() bool {
	return e.Retryable
}

// WrapError wraps an error with KMS context
func WrapError(op, keyID string, err error, retryable bool) error {
	if err == nil {
		return nil
	}

	return &KMSError{
		Op:        op,
		KeyID:     keyID,
		Err:       err,
		Retryable: retryable,
	}
}

// IsKMSError checks if an error is a KMS error
func IsKMSError(err error) bool {
	var kmsErr *KMSError
	return errors.As(err, &kmsErr)
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	var kmsErr *KMSError
	if errors.As(err, &kmsErr) {
		return kmsErr.IsRetryable()
	}
	return false
}
