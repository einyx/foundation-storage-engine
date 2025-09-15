package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"
	
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
)

// StreamingMultipartHandler handles uploads with unknown size by chunking on the fly
type StreamingMultipartHandler struct {
	s3Client    *s3.S3
	bucket      string
	key         string
	uploadID    string
	partSize    int64
	partNumber  int
	buffer      []byte
	bufferPos   int
}

// NewStreamingMultipartHandler creates a handler for streaming uploads
func NewStreamingMultipartHandler(client *s3.S3, bucket, key, uploadID string) *StreamingMultipartHandler {
	return &StreamingMultipartHandler{
		s3Client:   client,
		bucket:     bucket,
		key:        key,
		uploadID:   uploadID,
		partSize:   5 * 1024 * 1024, // 5MB parts - small enough to avoid timeouts
		partNumber: 1,
		buffer:     make([]byte, 5*1024*1024),
		bufferPos:  0,
	}
}

// HandleStreamingUpload processes data as it arrives, creating parts on the fly
func (h *StreamingMultipartHandler) HandleStreamingUpload(ctx context.Context, reader io.Reader) ([]CompletedPart, error) {
	parts := []CompletedPart{}
	
	logrus.WithFields(logrus.Fields{
		"bucket":   h.bucket,
		"key":      h.key,
		"uploadID": h.uploadID,
		"partSize": h.partSize,
	}).Info("Starting streaming multipart upload with small parts")
	
	for {
		// Read data into buffer
		n, err := reader.Read(h.buffer[h.bufferPos:])
		if n > 0 {
			h.bufferPos += n
		}
		
		// If buffer is full or we hit EOF, upload the part
		if h.bufferPos >= len(h.buffer) || (err == io.EOF && h.bufferPos > 0) {
			partData := make([]byte, h.bufferPos)
			copy(partData, h.buffer[:h.bufferPos])
			
			// Upload this part
			etag, uploadErr := h.uploadPart(ctx, h.partNumber, partData)
			if uploadErr != nil {
				return nil, fmt.Errorf("failed to upload part %d: %w", h.partNumber, uploadErr)
			}
			
			parts = append(parts, CompletedPart{
				PartNumber: h.partNumber,
				ETag:       etag,
			})
			
			logrus.WithFields(logrus.Fields{
				"partNumber": h.partNumber,
				"partSize":   len(partData),
				"etag":       etag,
			}).Debug("Uploaded streaming part")
			
			h.partNumber++
			h.bufferPos = 0
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading stream: %w", err)
		}
	}
	
	logrus.WithFields(logrus.Fields{
		"totalParts": len(parts),
		"uploadID":   h.uploadID,
	}).Info("Completed streaming multipart upload")
	
	return parts, nil
}

// uploadPart uploads a single part with timeout handling
func (h *StreamingMultipartHandler) uploadPart(ctx context.Context, partNumber int, data []byte) (string, error) {
	// Use a reasonable timeout for 5MB
	uploadCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	
	start := time.Now()
	
	input := &s3.UploadPartInput{
		Bucket:        aws.String(h.bucket),
		Key:           aws.String(h.key),
		UploadId:      aws.String(h.uploadID),
		PartNumber:    aws.Int64(int64(partNumber)),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	}
	
	resp, err := h.s3Client.UploadPartWithContext(uploadCtx, input)
	
	duration := time.Since(start)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"partNumber": partNumber,
			"partSize":   len(data),
			"duration":   duration,
		}).Error("Failed to upload part")
		return "", err
	}
	
	logrus.WithFields(logrus.Fields{
		"partNumber": partNumber,
		"partSize":   len(data),
		"duration":   duration,
		"etag":       aws.StringValue(resp.ETag),
	}).Debug("Part uploaded successfully")
	
	return aws.StringValue(resp.ETag), nil
}