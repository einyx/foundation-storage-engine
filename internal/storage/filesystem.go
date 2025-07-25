package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

type FileSystemBackend struct {
	baseDir    string
	bufferPool sync.Pool
}

// validateBucketName ensures a bucket name doesn't contain directory traversal sequences
func validateBucketName(bucket string) error {
	if bucket == "" {
		return errors.New("bucket name cannot be empty")
	}
	if strings.Contains(bucket, "..") {
		return errors.New("bucket name cannot contain '..'")
	}
	if strings.Contains(bucket, "/") || strings.Contains(bucket, "\\") {
		return errors.New("bucket name cannot contain path separators")
	}
	if bucket == "." {
		return errors.New("bucket name cannot be '.'")
	}
	return nil
}

// validateObjectKey ensures an object key doesn't contain directory traversal sequences
func validateObjectKey(key string) error {
	if key == "" {
		return errors.New("object key cannot be empty")
	}
	// Check for parent directory references
	if strings.Contains(key, "..") {
		return errors.New("object key cannot contain '..'")
	}
	// Check for absolute paths
	if strings.HasPrefix(key, "/") {
		return errors.New("object key cannot start with '/'")
	}
	// Check for Windows-style separators  
	if strings.Contains(key, "\\") {
		return errors.New("object key cannot contain backslashes")
	}
	return nil
}

// secureBucketPath safely constructs a bucket path
func (fs *FileSystemBackend) secureBucketPath(bucket string) (string, error) {
	if err := validateBucketName(bucket); err != nil {
		return "", err
	}
	
	fullPath := filepath.Join(fs.baseDir, bucket)
	
	// Ensure the resulting path is still within the base directory
	cleanPath := filepath.Clean(fullPath)
	cleanBase := filepath.Clean(fs.baseDir)
	
	if !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) && cleanPath != cleanBase {
		return "", errors.New("path traversal detected")
	}
	
	return cleanPath, nil
}

// secureObjectPath safely constructs an object path
func (fs *FileSystemBackend) secureObjectPath(bucket, key string) (string, error) {
	if err := validateBucketName(bucket); err != nil {
		return "", fmt.Errorf("invalid bucket name: %w", err)
	}
	if err := validateObjectKey(key); err != nil {
		return "", fmt.Errorf("invalid object key: %w", err)
	}
	
	fullPath := filepath.Join(fs.baseDir, bucket, key)
	
	// Ensure the resulting path is still within the base directory
	cleanPath := filepath.Clean(fullPath)
	cleanBase := filepath.Clean(fs.baseDir)
	
	if !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) && cleanPath != cleanBase {
		return "", errors.New("path traversal detected")
	}
	
	return cleanPath, nil
}

// secureUploadPath safely constructs an upload directory path
func (fs *FileSystemBackend) secureUploadPath(bucket, uploadID string) (string, error) {
	if err := validateBucketName(bucket); err != nil {
		return "", fmt.Errorf("invalid bucket name: %w", err)
	}
	if err := validateBucketName(uploadID); err != nil { // uploadID follows bucket naming rules
		return "", fmt.Errorf("invalid upload ID: %w", err)
	}
	
	fullPath := filepath.Join(fs.baseDir, bucket, ".uploads", uploadID)
	
	// Ensure the resulting path is still within the base directory
	cleanPath := filepath.Clean(fullPath)
	cleanBase := filepath.Clean(fs.baseDir)
	
	if !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) && cleanPath != cleanBase {
		return "", errors.New("path traversal detected")
	}
	
	return cleanPath, nil
}

func NewFileSystemBackend(cfg *config.FileSystemConfig) (*FileSystemBackend, error) {
	if cfg.BaseDir == "" {
		return nil, fmt.Errorf("base directory is required for filesystem backend")
	}

	// Ensure base directory exists
	if err := os.MkdirAll(cfg.BaseDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &FileSystemBackend{
		baseDir: cfg.BaseDir,
		bufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 1024*1024) // 1MB buffers for better large file handling
				return &buf
			},
		},
	}, nil
}

func (fs *FileSystemBackend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	entries, err := os.ReadDir(fs.baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read base directory: %w", err)
	}

	var buckets []BucketInfo
	for _, entry := range entries {
		if entry.IsDir() {
			info, err := entry.Info()
			if err == nil {
				buckets = append(buckets, BucketInfo{
					Name:         entry.Name(),
					CreationDate: info.ModTime(),
				})
			}
		}
	}

	return buckets, nil
}

func (fs *FileSystemBackend) CreateBucket(ctx context.Context, bucket string) error {
	bucketPath, err := fs.secureBucketPath(bucket)
	if err != nil {
		return fmt.Errorf("invalid bucket name: %w", err)
	}
	return os.MkdirAll(bucketPath, 0750)
}

func (fs *FileSystemBackend) DeleteBucket(ctx context.Context, bucket string) error {
	bucketPath, err := fs.secureBucketPath(bucket)
	if err != nil {
		return fmt.Errorf("invalid bucket name: %w", err)
	}
	return os.RemoveAll(bucketPath)
}

func (fs *FileSystemBackend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	bucketPath, err := fs.secureBucketPath(bucket)
	if err != nil {
		return false, fmt.Errorf("invalid bucket name: %w", err)
	}
	info, err := os.Stat(bucketPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

func (fs *FileSystemBackend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	// Default to using delimiter for backward compatibility
	return fs.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, "/", maxKeys)
}

func (fs *FileSystemBackend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	bucketPath, err := fs.secureBucketPath(bucket)
	if err != nil {
		return nil, fmt.Errorf("invalid bucket name: %w", err)
	}

	result := &ListObjectsResult{
		Contents:       make([]ObjectInfo, 0),
		CommonPrefixes: make([]string, 0),
	}

	// Track common prefixes for delimiter support
	prefixSet := make(map[string]bool)
	count := 0

	err = filepath.Walk(bucketPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || count >= maxKeys {
			return nil
		}

		// Get relative path from bucket
		relPath, err := filepath.Rel(bucketPath, path)
		if err != nil {
			return nil
		}

		// Convert to Unix-style path for S3 compatibility
		key := filepath.ToSlash(relPath)

		// Skip the root directory itself
		if key == "." {
			return nil
		}

		// Apply prefix filter
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}

		// Apply marker filter
		if marker != "" && key <= marker {
			return nil
		}

		// Handle delimiter logic
		if delimiter != "" && prefix != "" {
			// Remove prefix to find the next component
			afterPrefix := strings.TrimPrefix(key, prefix)
			if afterPrefix != key { // Has the prefix
				delimIndex := strings.Index(afterPrefix, delimiter)
				if delimIndex >= 0 {
					// This is a "directory" - add to common prefixes
					commonPrefix := prefix + afterPrefix[:delimIndex+len(delimiter)]
					if !prefixSet[commonPrefix] {
						prefixSet[commonPrefix] = true
						result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix)
						count++
					}
					return nil
				}
			}
		} else if delimiter != "" {
			// No prefix, check for delimiter from start
			delimIndex := strings.Index(key, delimiter)
			if delimIndex >= 0 {
				// This is a "directory" - add to common prefixes
				commonPrefix := key[:delimIndex+len(delimiter)]
				if !prefixSet[commonPrefix] {
					prefixSet[commonPrefix] = true
					result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix)
					count++
				}
				return nil
			}
		}

		// Regular file - add to contents if not a directory and not a metadata file
		if !info.IsDir() && !strings.HasSuffix(key, ".meta") {
			// Load metadata for this object
			objectPath := filepath.Join(bucketPath, key)
			metadata := make(map[string]string)
			metadataPath := objectPath + ".meta"
			if metadataBytes, err := os.ReadFile(metadataPath); err == nil { //nolint:gosec // metadataPath is controlled
				_ = json.Unmarshal(metadataBytes, &metadata)
			}

			// Set default content type if not in metadata
			contentType := metadata["Content-Type"]
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			result.Contents = append(result.Contents, ObjectInfo{
				Key:          key,
				Size:         info.Size(),
				ETag:         fmt.Sprintf("\"%x\"", info.ModTime().UnixNano()),
				LastModified: info.ModTime(),
				ContentType:  contentType,
				Metadata:     metadata,
			})
			count++
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk bucket directory: %w", err)
	}

	result.IsTruncated = count >= maxKeys
	return result, nil
}

func (fs *FileSystemBackend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	objectPath, err := fs.secureObjectPath(bucket, key)
	if err != nil {
		return nil, fmt.Errorf("invalid path parameters: %w", err)
	}

	info, err := os.Stat(objectPath)
	if err != nil {
		return nil, fmt.Errorf("object not found: %w", err)
	}

	file, err := os.Open(objectPath) //nolint:gosec // objectPath is controlled
	if err != nil {
		return nil, fmt.Errorf("failed to open object: %w", err)
	}

	// Load metadata from .meta file if it exists
	metadata := make(map[string]string)
	metadataPath := objectPath + ".meta"
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil { //nolint:gosec // metadataPath is controlled
		_ = json.Unmarshal(metadataBytes, &metadata)
	}

	// Set default content type if not in metadata
	contentType := metadata["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	return &Object{
		Body:         file,
		ContentType:  contentType,
		Size:         info.Size(),
		ETag:         fmt.Sprintf("\"%x\"", info.ModTime().UnixNano()),
		LastModified: info.ModTime(),
		Metadata:     metadata,
	}, nil
}

func (fs *FileSystemBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	objectPath, err := fs.secureObjectPath(bucket, key)
	if err != nil {
		return fmt.Errorf("invalid path parameters: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(objectPath), 0750); err != nil {
		return fmt.Errorf("failed to create object directory: %w", err)
	}

	file, err := os.Create(objectPath) //nolint:gosec // objectPath is controlled
	if err != nil {
		return fmt.Errorf("failed to create object file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Use buffer pool for efficient copying
	bufPtr := fs.bufferPool.Get().(*[]byte)
	defer fs.bufferPool.Put(bufPtr)
	buf := *bufPtr

	_, err = io.CopyBuffer(file, reader, buf)
	if err != nil {
		return fmt.Errorf("failed to write object data: %w", err)
	}

	// Save metadata to .meta file if provided
	if len(metadata) > 0 {
		metadataPath := objectPath + ".meta"
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		if err := os.WriteFile(metadataPath, metadataBytes, 0600); err != nil {
			return fmt.Errorf("failed to write metadata file: %w", err)
		}
	}

	return nil
}

func (fs *FileSystemBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	objectPath, err := fs.secureObjectPath(bucket, key)
	if err != nil {
		return fmt.Errorf("invalid path parameters: %w", err)
	}

	// Remove the object file
	err = os.Remove(objectPath)
	if os.IsNotExist(err) {
		return nil // S3 behavior: deleting non-existent object succeeds
	}

	// Also remove metadata file if it exists
	metadataPath := objectPath + ".meta"
	_ = os.Remove(metadataPath) // Ignore errors - metadata file might not exist

	return err
}

func (fs *FileSystemBackend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	objectPath, err := fs.secureObjectPath(bucket, key)
	if err != nil {
		return nil, fmt.Errorf("invalid path parameters: %w", err)
	}

	info, err := os.Stat(objectPath)
	if err != nil {
		return nil, fmt.Errorf("object not found: %w", err)
	}

	// Load metadata from .meta file if it exists
	metadata := make(map[string]string)
	metadataPath := objectPath + ".meta"
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil { //nolint:gosec // metadataPath is controlled
		_ = json.Unmarshal(metadataBytes, &metadata)
	}

	// Set default content type if not in metadata
	contentType := metadata["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	return &ObjectInfo{
		Key:          key,
		Size:         info.Size(),
		ETag:         fmt.Sprintf("\"%x\"", info.ModTime().UnixNano()),
		LastModified: info.ModTime(),
		ContentType:  contentType,
		Metadata:     metadata,
	}, nil
}

func (fs *FileSystemBackend) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	return &ACL{
		Owner: Owner{
			ID:          "filesystem",
			DisplayName: "FileSystem",
		},
		Grants: []Grant{
			{
				Grantee: Grantee{
					Type:        "CanonicalUser",
					ID:          "filesystem",
					DisplayName: "FileSystem",
				},
				Permission: "FULL_CONTROL",
			},
		},
	}, nil
}

func (fs *FileSystemBackend) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	// No-op for filesystem backend
	return nil
}

func (fs *FileSystemBackend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	uploadID := fmt.Sprintf("%s-%d", key, time.Now().UnixNano())

	// Create a temporary directory for multipart upload
	uploadDir, err := fs.secureUploadPath(bucket, uploadID)
	if err != nil {
		return "", fmt.Errorf("invalid path parameters: %w", err)
	}
	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create upload directory: %w", err)
	}

	return uploadID, nil
}

func (fs *FileSystemBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	uploadDir, err := fs.secureUploadPath(bucket, uploadID)
	if err != nil {
		return "", fmt.Errorf("invalid path parameters: %w", err)
	}
	partPath := filepath.Join(uploadDir, fmt.Sprintf("part-%d", partNumber))

	file, err := os.Create(partPath) //nolint:gosec // partPath is controlled
	if err != nil {
		return "", fmt.Errorf("failed to create part file: %w", err)
	}
	defer func() { _ = file.Close() }()

	bufPtr := fs.bufferPool.Get().(*[]byte)
	defer fs.bufferPool.Put(bufPtr)
	buf := *bufPtr

	_, err = io.CopyBuffer(file, reader, buf)
	if err != nil {
		return "", fmt.Errorf("failed to write part data: %w", err)
	}

	return fmt.Sprintf("\"%d\"", partNumber), nil
}

func (fs *FileSystemBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	uploadDir, err := fs.secureUploadPath(bucket, uploadID)
	if err != nil {
		return fmt.Errorf("invalid upload path parameters: %w", err)
	}
	
	objectPath, err := fs.secureObjectPath(bucket, key)
	if err != nil {
		return fmt.Errorf("invalid object path parameters: %w", err)
	}

	// Ensure object directory exists
	if err := os.MkdirAll(filepath.Dir(objectPath), 0750); err != nil {
		return fmt.Errorf("failed to create object directory: %w", err)
	}

	file, err := os.Create(objectPath) //nolint:gosec // objectPath is controlled
	if err != nil {
		return fmt.Errorf("failed to create object file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Use concurrent readers with sequential writes for better performance
	const maxConcurrentReads = 3
	type partReader struct {
		partNumber int
		reader     io.ReadCloser
		err        error
	}
	
	// Channel for part readers
	readerChan := make(chan partReader, maxConcurrentReads)
	
	// Start goroutine to open part files concurrently
	go func() {
		defer close(readerChan)
		
		// Process parts in batches
		for i := 0; i < len(parts); i += maxConcurrentReads {
			batch := parts[i:min(i+maxConcurrentReads, len(parts))]
			
			// Open files in parallel
			readers := make([]partReader, len(batch))
			var wg sync.WaitGroup
			
			for j, part := range batch {
				wg.Add(1)
				go func(idx int, p CompletedPart) {
					defer wg.Done()
					partPath := filepath.Join(uploadDir, fmt.Sprintf("part-%d", p.PartNumber))
					file, err := os.Open(partPath) //nolint:gosec // partPath is controlled
					readers[idx] = partReader{
						partNumber: p.PartNumber,
						reader:     file,
						err:        err,
					}
				}(j, part)
			}
			
			wg.Wait()
			
			// Send readers in order
			for _, r := range readers {
				select {
				case readerChan <- r:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	
	// Write parts sequentially to maintain order
	for reader := range readerChan {
		if reader.err != nil {
			return fmt.Errorf("failed to open part %d: %w", reader.partNumber, reader.err)
		}
		
		bufPtr := fs.bufferPool.Get().(*[]byte)
		buf := *bufPtr
		_, err = io.CopyBuffer(file, reader.reader, buf)
		_ = reader.reader.Close()
		fs.bufferPool.Put(bufPtr)
		
		if err != nil {
			return fmt.Errorf("failed to copy part %d: %w", reader.partNumber, err)
		}
	}

	// Clean up upload directory
	_ = os.RemoveAll(uploadDir)

	return nil
}

func (fs *FileSystemBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	uploadDir, err := fs.secureUploadPath(bucket, uploadID)
	if err != nil {
		return fmt.Errorf("invalid path parameters: %w", err)
	}
	return os.RemoveAll(uploadDir)
}

func (fs *FileSystemBackend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	uploadDir, err := fs.secureUploadPath(bucket, uploadID)
	if err != nil {
		return nil, fmt.Errorf("invalid path parameters: %w", err)
	}

	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read upload directory: %w", err)
	}

	result := &ListPartsResult{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
		Parts:    make([]Part, 0),
	}

	count := 0
	for _, entry := range entries {
		if count >= maxParts {
			break
		}

		if strings.HasPrefix(entry.Name(), "part-") {
			var partNumber int
			if _, err := fmt.Sscanf(entry.Name(), "part-%d", &partNumber); err == nil {
				if partNumber > partNumberMarker {
					info, err := entry.Info()
					if err == nil {
						result.Parts = append(result.Parts, Part{
							PartNumber:   partNumber,
							ETag:         fmt.Sprintf("\"%d\"", partNumber),
							Size:         info.Size(),
							LastModified: info.ModTime(),
						})
						count++
					}
				}
			}
		}
	}

	result.IsTruncated = count >= maxParts
	return result, nil
}
