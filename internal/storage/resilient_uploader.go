package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
)

// ResilientUploader handles uploads to problematic servers
type ResilientUploader struct {
	s3Client *s3.S3
	config   ResilientConfig
}

type ResilientConfig struct {
	InitialPartSize   int64         // Starting part size
	MinPartSize       int64         // Minimum part size
	MaxRetries        int           // Max retries per part
	RetryDelay        time.Duration // Initial retry delay
	ProgressCallback  func(uploaded, total int64)
}

// NewResilientUploader creates an uploader for problematic servers
func NewResilientUploader(client *s3.S3) *ResilientUploader {
	return &ResilientUploader{
		s3Client: client,
		config: ResilientConfig{
			InitialPartSize: 5 * 1024 * 1024,  // 5MB
			MinPartSize:     1 * 1024 * 1024,  // 1MB minimum
			MaxRetries:      5,
			RetryDelay:      2 * time.Second,
		},
	}
}

// UploadWithRetry uploads a file with aggressive retry logic
func (ru *ResilientUploader) UploadWithRetry(ctx context.Context, bucket, key string, reader io.Reader, size int64) error {
	// Start multipart upload
	initResp, err := ru.s3Client.CreateMultipartUploadWithContext(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to initiate multipart upload: %w", err)
	}

	uploadID := aws.StringValue(initResp.UploadId)
	logrus.WithField("uploadId", uploadID).Info("Started resilient multipart upload")

	// Upload parts with adaptive sizing
	var completedParts []*s3.CompletedPart
	partNumber := int64(1)
	totalUploaded := int64(0)
	currentPartSize := ru.config.InitialPartSize
	consecutiveFailures := 0

	// Create a buffer for reading
	buffer := make([]byte, currentPartSize)

	// Handle unknown size (size == 0) by reading until EOF
	for size == 0 || totalUploaded < size {
		// Adjust part size based on failures
		if consecutiveFailures > 2 && currentPartSize > ru.config.MinPartSize {
			currentPartSize = currentPartSize / 2
			if currentPartSize < ru.config.MinPartSize {
				currentPartSize = ru.config.MinPartSize
			}
			logrus.WithField("newPartSize", currentPartSize).Warn("Reduced part size due to failures")
			buffer = make([]byte, currentPartSize)
			consecutiveFailures = 0
		}

		// Read part data
		toRead := currentPartSize
		if size > 0 && totalUploaded+toRead > size {
			toRead = size - totalUploaded
		}

		n, err := io.ReadFull(reader, buffer[:toRead])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read data: %w", err)
		}

		if n == 0 {
			break
		}

		// Upload part with retries
		var etag string
		for attempt := 0; attempt < ru.config.MaxRetries; attempt++ {
			if attempt > 0 {
				delay := time.Duration(attempt) * ru.config.RetryDelay
				logrus.WithFields(logrus.Fields{
					"part":    partNumber,
					"attempt": attempt + 1,
					"delay":   delay,
				}).Warn("Retrying part upload")
				time.Sleep(delay)
			}

			// Create a deadline for this part
			partCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			
			resp, err := ru.s3Client.UploadPartWithContext(partCtx, &s3.UploadPartInput{
				Bucket:     aws.String(bucket),
				Key:        aws.String(key),
				UploadId:   aws.String(uploadID),
				PartNumber: aws.Int64(partNumber),
				Body:       aws.ReadSeekCloser(NewBytesReadSeeker(buffer[:n])),
				ContentLength: aws.Int64(int64(n)),
			})
			
			cancel()

			if err == nil {
				etag = aws.StringValue(resp.ETag)
				consecutiveFailures = 0
				break
			}

			logrus.WithError(err).WithField("part", partNumber).Error("Part upload failed")
			consecutiveFailures++

			// If context expired, create a new one
			if ctx.Err() != nil {
				return fmt.Errorf("upload cancelled: %w", ctx.Err())
			}
		}

		if etag == "" {
			// All retries failed, abort
			ru.s3Client.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(bucket),
				Key:      aws.String(key),
				UploadId: aws.String(uploadID),
			})
			return fmt.Errorf("failed to upload part %d after %d attempts", partNumber, ru.config.MaxRetries)
		}

		completedParts = append(completedParts, &s3.CompletedPart{
			ETag:       aws.String(etag),
			PartNumber: aws.Int64(partNumber),
		})

		totalUploaded += int64(n)
		partNumber++

		// Progress callback
		if ru.config.ProgressCallback != nil && size > 0 {
			ru.config.ProgressCallback(totalUploaded, size)
		}

		// Add delay between parts to avoid overwhelming server
		if size == 0 || totalUploaded < size {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Complete multipart upload
	_, err = ru.s3Client.CompleteMultipartUploadWithContext(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})

	if err != nil {
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"parts": len(completedParts),
		"size":  totalUploaded,
	}).Info("Resilient upload completed")

	return nil
}