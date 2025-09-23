package storage

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
)

// MultipartUploader handles concurrent multipart uploads for better performance
type MultipartUploader struct {
	client      *s3.S3
	bucket      string
	key         string
	uploadID    string
	partSize    int64
	concurrency int
	parts       sync.Map
	totalParts  int32
	uploadedParts int32
}

// UploadStats tracks upload performance
type UploadStats struct {
	BytesUploaded int64
	PartsUploaded int32
	StartTime     time.Time
	mu            sync.Mutex
}

// GetThroughput returns current upload throughput in MB/s
func (s *UploadStats) GetThroughput() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	elapsed := time.Since(s.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(s.BytesUploaded) / elapsed / 1024 / 1024
}

// NewMultipartUploader creates a new concurrent uploader
func NewMultipartUploader(client *s3.S3, bucket, key, uploadID string, partSize int64, concurrency int) *MultipartUploader {
	if concurrency <= 0 {
		concurrency = 10
	}
	return &MultipartUploader{
		client:      client,
		bucket:      bucket,
		key:         key,
		uploadID:    uploadID,
		partSize:    partSize,
		concurrency: concurrency,
	}
}

// UploadStream uploads data from reader using concurrent parts
func (u *MultipartUploader) UploadStream(ctx context.Context, reader io.Reader, totalSize int64) error {
	stats := &UploadStats{StartTime: time.Now()}
	
	// Channel for part data
	type partData struct {
		number int64
		data   []byte
		size   int64
	}
	
	partChan := make(chan partData, u.concurrency*2)
	errChan := make(chan error, u.concurrency)
	
	// Start upload workers
	var wg sync.WaitGroup
	for i := 0; i < u.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for part := range partChan {
				if err := u.uploadPart(ctx, part.number, part.data, stats); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
			}
		}()
	}
	
	// Reader goroutine - read and queue parts
	go func() {
		defer close(partChan)
		
		partNumber := int64(1)
		buffer := make([]byte, u.partSize)
		
		for {
			n, err := io.ReadFull(reader, buffer)
			if n > 0 {
				// Make a copy of the data
				data := make([]byte, n)
				copy(data, buffer[:n])
				
				select {
				case partChan <- partData{
					number: partNumber,
					data:   data,
					size:   int64(n),
				}:
					partNumber++
					atomic.AddInt32(&u.totalParts, 1)
				case <-ctx.Done():
					return
				}
			}
			
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				select {
				case errChan <- fmt.Errorf("read error: %w", err):
				default:
				}
				return
			}
		}
	}()
	
	// Wait for uploads to complete
	wg.Wait()
	
	// Check for errors
	select {
	case err := <-errChan:
		return err
	default:
	}
	
	// Log final stats
	logrus.WithFields(logrus.Fields{
		"bucket":     u.bucket,
		"key":        u.key,
		"parts":      atomic.LoadInt32(&u.uploadedParts),
		"throughput": fmt.Sprintf("%.2f MB/s", stats.GetThroughput()),
		"duration":   time.Since(stats.StartTime),
	}).Info("Multipart upload completed")
	
	return nil
}

func (u *MultipartUploader) uploadPart(ctx context.Context, partNumber int64, data []byte, stats *UploadStats) error {
	input := &s3.UploadPartInput{
		Bucket:     aws.String(u.bucket),
		Key:        aws.String(u.key),
		UploadId:   aws.String(u.uploadID),
		PartNumber: aws.Int64(partNumber),
		Body:       aws.ReadSeekCloser(NewBytesReadSeeker(data)),
		ContentLength: aws.Int64(int64(len(data))),
	}
	
	resp, err := u.client.UploadPartWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("upload part %d failed: %w", partNumber, err)
	}
	
	// Store completed part info
	u.parts.Store(partNumber, &s3.CompletedPart{
		ETag:       resp.ETag,
		PartNumber: aws.Int64(partNumber),
	})
	
	// Update stats
	atomic.AddInt32(&u.uploadedParts, 1)
	stats.mu.Lock()
	stats.BytesUploaded += int64(len(data))
	stats.PartsUploaded = atomic.LoadInt32(&u.uploadedParts)
	stats.mu.Unlock()
	
	// Log progress every 10 parts
	if partNumber%10 == 0 {
		logrus.WithFields(logrus.Fields{
			"part":       partNumber,
			"throughput": fmt.Sprintf("%.2f MB/s", stats.GetThroughput()),
		}).Debug("Upload progress")
	}
	
	return nil
}

// GetCompletedParts returns all completed parts for finalizing the upload
func (u *MultipartUploader) GetCompletedParts() []*s3.CompletedPart {
	var parts []*s3.CompletedPart
	
	// Collect all parts
	for i := int64(1); i <= int64(atomic.LoadInt32(&u.totalParts)); i++ {
		if val, ok := u.parts.Load(i); ok {
			parts = append(parts, val.(*s3.CompletedPart))
		}
	}
	
	return parts
}

// BytesReadSeeker implements io.ReadSeeker for byte slices
type BytesReadSeeker struct {
	data []byte
	pos  int
}

func NewBytesReadSeeker(data []byte) *BytesReadSeeker {
	return &BytesReadSeeker{data: data}
}

func (b *BytesReadSeeker) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *BytesReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = int64(b.pos) + offset
	case io.SeekEnd:
		newPos = int64(len(b.data)) + offset
	default:
		return 0, fmt.Errorf("invalid whence")
	}
	
	if newPos < 0 || newPos > int64(len(b.data)) {
		return 0, fmt.Errorf("seek out of range")
	}
	
	b.pos = int(newPos)
	return newPos, nil
}

func (b *BytesReadSeeker) Close() error {
	return nil
}