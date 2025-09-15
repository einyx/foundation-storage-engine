package storage

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
	
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
)

// MultipartStreamUploader handles large multipart uploads efficiently
type MultipartStreamUploader struct {
	client     *s3.S3
	bucket     string
	key        string
	uploadID   string
	partSize   int64
	numWorkers int
}

// NewMultipartStreamUploader creates a new uploader
func NewMultipartStreamUploader(client *s3.S3, bucket, key, uploadID string) *MultipartStreamUploader {
	return &MultipartStreamUploader{
		client:     client,
		bucket:     bucket,
		key:        key,
		uploadID:   uploadID,
		partSize:   64 * 1024 * 1024, // 64MB default - large enough to be efficient, small enough to avoid timeouts
		numWorkers: 4,                 // Parallel workers
	}
}

// UploadStream uploads data from a reader using parallel multipart uploads
func (u *MultipartStreamUploader) UploadStream(ctx context.Context, reader io.Reader, totalSize int64) ([]CompletedPart, error) {
	// Create channels for work distribution
	type partJob struct {
		partNumber int
		data       []byte
	}
	
	jobChan := make(chan partJob, u.numWorkers*2)
	resultChan := make(chan struct {
		partNumber int
		etag       string
		err        error
	}, u.numWorkers*2)
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < u.numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobChan {
				etag, err := u.uploadPart(ctx, job.partNumber, job.data)
				resultChan <- struct {
					partNumber int
					etag       string
					err        error
				}{job.partNumber, etag, err}
			}
		}(i)
	}
	
	// Start result collector
	parts := make([]CompletedPart, 0)
	partsMu := sync.Mutex{}
	errChan := make(chan error, 1)
	
	go func() {
		for result := range resultChan {
			if result.err != nil {
				select {
				case errChan <- result.err:
				default:
				}
				return
			}
			
			partsMu.Lock()
			parts = append(parts, CompletedPart{
				PartNumber: result.partNumber,
				ETag:       result.etag,
			})
			partsMu.Unlock()
		}
	}()
	
	// Read and distribute work
	partNumber := 1
	totalRead := int64(0)
	buffer := make([]byte, u.partSize)
	
	for totalRead < totalSize {
		// Read up to partSize
		n, err := io.ReadFull(reader, buffer)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if n == 0 {
				break
			}
		} else if err != nil {
			close(jobChan)
			return nil, fmt.Errorf("error reading data: %w", err)
		}
		
		// Send job to workers
		partData := make([]byte, n)
		copy(partData, buffer[:n])
		
		select {
		case jobChan <- partJob{partNumber: partNumber, data: partData}:
			partNumber++
			totalRead += int64(n)
			
			logrus.WithFields(logrus.Fields{
				"partNumber": partNumber - 1,
				"partSize":   n,
				"totalRead":  totalRead,
				"progress":   fmt.Sprintf("%.1f%%", float64(totalRead)/float64(totalSize)*100),
			}).Debug("Queued part for upload")
			
		case err := <-errChan:
			close(jobChan)
			return nil, fmt.Errorf("upload failed: %w", err)
		case <-ctx.Done():
			close(jobChan)
			return nil, ctx.Err()
		}
		
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}
	
	// Close job channel and wait for workers
	close(jobChan)
	wg.Wait()
	close(resultChan)
	
	// Check for errors
	select {
	case err := <-errChan:
		return nil, err
	default:
	}
	
	return parts, nil
}

// uploadPart uploads a single part
func (u *MultipartStreamUploader) uploadPart(ctx context.Context, partNumber int, data []byte) (string, error) {
	start := time.Now()
	
	input := &s3.UploadPartInput{
		Bucket:        aws.String(u.bucket),
		Key:           aws.String(u.key),
		UploadId:      aws.String(u.uploadID),
		PartNumber:    aws.Int64(int64(partNumber)),
		Body:          aws.ReadSeekCloser(newBytesReaderCloser(data)),
		ContentLength: aws.Int64(int64(len(data))),
	}
	
	// Use a timeout appropriate for the part size
	// Assume minimum 1MB/s upload speed
	timeout := time.Duration(len(data)/1024/1024+30) * time.Second
	uploadCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	resp, err := u.client.UploadPartWithContext(uploadCtx, input)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"partNumber": partNumber,
			"partSize":   len(data),
			"duration":   time.Since(start),
		}).Error("Failed to upload part")
		return "", err
	}
	
	logrus.WithFields(logrus.Fields{
		"partNumber": partNumber,
		"partSize":   len(data),
		"duration":   time.Since(start),
		"etag":       aws.StringValue(resp.ETag),
	}).Info("Successfully uploaded part")
	
	return aws.StringValue(resp.ETag), nil
}

// bytesReaderCloser wraps []byte to provide ReadSeekCloser interface
type bytesReaderCloser struct {
	data []byte
	pos  int64
}

func newBytesReaderCloser(data []byte) *bytesReaderCloser {
	return &bytesReaderCloser{data: data}
}

func (b *bytesReaderCloser) Read(p []byte) (n int, err error) {
	if b.pos >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n = copy(p, b.data[b.pos:])
	b.pos += int64(n)
	return n, nil
}

func (b *bytesReaderCloser) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = b.pos + offset
	case io.SeekEnd:
		newPos = int64(len(b.data)) + offset
	}
	if newPos < 0 || newPos > int64(len(b.data)) {
		return b.pos, fmt.Errorf("seek out of range")
	}
	b.pos = newPos
	return b.pos, nil
}

func (b *bytesReaderCloser) Close() error {
	return nil
}