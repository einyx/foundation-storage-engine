package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// MultipartWrapper wraps a storage backend to handle slow multipart uploads better
type MultipartWrapper struct {
	Backend
	slowBackendTimeout time.Duration
}

// NewMultipartWrapper creates a wrapper that handles slow backends better
func NewMultipartWrapper(backend Backend, timeout time.Duration) *MultipartWrapper {
	return &MultipartWrapper{
		Backend:            backend,
		slowBackendTimeout: timeout,
	}
}

// UploadPart overrides the default upload part with better timeout handling
func (m *MultipartWrapper) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	logger := logrus.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"size":       size,
	})

	// Check if this is going to the slow backend
	isSlowBackend := m.isSlowBackend(bucket)
	if isSlowBackend {
		logger.Warn("Uploading to known slow backend - using extended timeout")
	}

	// Create a context with extended timeout for slow backends
	uploadCtx := ctx
	if isSlowBackend {
		var cancel context.CancelFunc
		uploadCtx, cancel = context.WithTimeout(context.Background(), m.slowBackendTimeout)
		defer cancel()
	}

	// Try the upload with retries for slow backends
	var lastErr error
	maxRetries := 1
	if isSlowBackend {
		maxRetries = 3
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		start := time.Now()
		
		// For retries, we need to re-read the data if possible
		var uploadReader io.Reader = reader
		if attempt > 1 {
			// If we can't seek back, we can't retry
			if seeker, ok := reader.(io.Seeker); ok {
				if _, err := seeker.Seek(0, io.SeekStart); err != nil {
					logger.WithError(err).Error("Failed to seek reader for retry")
					return "", lastErr
				}
			} else {
				logger.Warn("Cannot retry upload - reader is not seekable")
				return "", lastErr
			}
		}

		etag, err := m.Backend.UploadPart(uploadCtx, bucket, key, uploadID, partNumber, uploadReader, size)
		duration := time.Since(start)

		if err == nil {
			logger.WithFields(logrus.Fields{
				"attempt":  attempt,
				"duration": duration,
				"etag":     etag,
			}).Info("Part upload succeeded")
			return etag, nil
		}

		lastErr = err
		logger.WithError(err).WithFields(logrus.Fields{
			"attempt":  attempt,
			"duration": duration,
		}).Warn("Part upload failed")

		// Check if it's a timeout
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			if attempt < maxRetries {
				backoff := time.Duration(attempt) * 5 * time.Second
				logger.WithField("backoff", backoff).Info("Retrying after timeout")
				time.Sleep(backoff)
				continue
			}
		}

		// For non-timeout errors, don't retry
		break
	}

	return "", fmt.Errorf("part upload failed after %d attempts: %w", maxRetries, lastErr)
}

// isSlowBackend checks if this bucket is configured to use a slow backend
func (m *MultipartWrapper) isSlowBackend(bucket string) bool {
	// Check if this is the known slow backend
	// This could be made configurable
	return bucket == "warehouse" || bucket == "dev-terraform-managed-bucket" || bucket == "abccargo"
}

// CompleteMultipartUpload with extended timeout for slow backends
func (m *MultipartWrapper) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	logger := logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
		"parts":    len(parts),
	})

	// Use extended timeout for slow backends
	completeCtx := ctx
	if m.isSlowBackend(bucket) {
		var cancel context.CancelFunc
		completeCtx, cancel = context.WithTimeout(context.Background(), m.slowBackendTimeout)
		defer cancel()
		logger.Warn("Completing multipart upload on slow backend - using extended timeout")
	}

	start := time.Now()
	err := m.Backend.CompleteMultipartUpload(completeCtx, bucket, key, uploadID, parts)
	duration := time.Since(start)

	if err != nil {
		logger.WithError(err).WithField("duration", duration).Error("Failed to complete multipart upload")
		return err
	}

	logger.WithField("duration", duration).Info("Multipart upload completed successfully")
	return nil
}