// Package storage provides storage backend implementations for Azure Blob Storage.
package storage

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // MD5 is required for Azure ETag compatibility
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/sirupsen/logrus"

	"github.com/einyx/s3proxy-go/internal/config"
)

type AzureBackend struct {
	serviceURL    azblob.ServiceURL
	credential    azblob.Credential
	accountName   string
	containerName string
	bufferPool    sync.Pool
}

func NewAzureBackend(cfg *config.AzureStorageConfig) (*AzureBackend, error) {
	var credential azblob.Credential
	var err error

	if cfg.UseSAS {
		credential = azblob.NewAnonymousCredential()
	} else {
		credential, err = azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials: %w", err)
		}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net", cfg.AccountName)
	}

	if cfg.UseSAS && cfg.SASToken != "" {
		if !strings.Contains(endpoint, "?") {
			endpoint += "?" + cfg.SASToken
		} else {
			endpoint += "&" + cfg.SASToken
		}
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	containerName := cfg.ContainerName
	if containerName == "" {
		containerName = "$root"
	}

	// AZURE SDK: Ultra-optimized pipeline for maximum performance
	pipelineOptions := azblob.PipelineOptions{
		Retry: azblob.RetryOptions{
			Policy:        azblob.RetryPolicyExponential,
			MaxTries:      2,                      // Reduced retries for faster failures
			TryTimeout:    120 * time.Second,      // Increased timeout for large files
			RetryDelay:    500 * time.Millisecond, // Faster retry
			MaxRetryDelay: 5 * time.Second,        // Reduced max delay
		},
		Telemetry: azblob.TelemetryOptions{
			Value: "s3proxy-turbo/2.0",
		},
		// Note: HTTPSender customization is not available in this SDK version
		// The SDK will use default HTTP client settings
	}
	pipeline := azblob.NewPipeline(credential, pipelineOptions)
	serviceURL := azblob.NewServiceURL(*u, pipeline)

	return &AzureBackend{
		serviceURL:    serviceURL,
		credential:    credential,
		accountName:   cfg.AccountName,
		containerName: containerName,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 1024*1024) // 1MB buffers for better performance (16x increase)
			},
		},
	}, nil
}

func (a *AzureBackend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	var buckets []BucketInfo

	for marker := (azblob.Marker{}); marker.NotDone(); {
		listContainer, err := a.serviceURL.ListContainersSegment(ctx, marker, azblob.ListContainersSegmentOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}

		for _, container := range listContainer.ContainerItems {
			buckets = append(buckets, BucketInfo{
				Name:         container.Name,
				CreationDate: container.Properties.LastModified,
			})
		}

		marker = listContainer.NextMarker
	}

	return buckets, nil
}

func (a *AzureBackend) CreateBucket(ctx context.Context, bucket string) error {
	containerURL := a.serviceURL.NewContainerURL(bucket)
	_, err := containerURL.Create(ctx, azblob.Metadata{}, azblob.PublicAccessNone)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	return nil
}

func (a *AzureBackend) DeleteBucket(ctx context.Context, bucket string) error {
	containerURL := a.serviceURL.NewContainerURL(bucket)
	_, err := containerURL.Delete(ctx, azblob.ContainerAccessConditions{})
	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}
	return nil
}

func (a *AzureBackend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	containerURL := a.serviceURL.NewContainerURL(bucket)
	_, err := containerURL.GetProperties(ctx, azblob.LeaseAccessConditions{})
	if err != nil {
		if stgErr, ok := err.(azblob.StorageError); ok {
			if stgErr.ServiceCode() == azblob.ServiceCodeContainerNotFound {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func (a *AzureBackend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	// Default to using delimiter for backward compatibility
	return a.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, "/", maxKeys)
}

func (a *AzureBackend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	containerURL := a.serviceURL.NewContainerURL(bucket)

	options := azblob.ListBlobsSegmentOptions{
		Prefix: prefix,
		MaxResults: func() int32 {
			if maxKeys > 0x7FFFFFFF {
				return 0x7FFFFFFF
			}
			return int32(maxKeys) //nolint:gosec // maxKeys is bounded by check above
		}(),
	}

	result := &ListObjectsResult{
		Contents:       make([]ObjectInfo, 0),
		CommonPrefixes: make([]string, 0),
	}

	azMarker := azblob.Marker{}
	if marker != "" {
		azMarker.Val = &marker
	}

	// Azure Blob Storage uses hierarchical listing
	if delimiter != "" {
		resp, err := containerURL.ListBlobsHierarchySegment(ctx, azMarker, delimiter, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list blobs: %w", err)
		}

		// Add blob items
		for _, blob := range resp.Segment.BlobItems {
			key := blob.Name
			// Convert .dir blobs back to directory names
			if strings.HasSuffix(key, "/.dir") {
				// Check if this is a directory marker
				if blob.Metadata != nil {
					if isDir, exists := blob.Metadata["s3proxyDirectoryMarker"]; exists && isDir == "true" {
						if origKey, origExists := blob.Metadata["s3proxyOriginalKey"]; origExists {
							key = origKey
						} else {
							// Fallback: convert .dir suffix back to /
							key = strings.TrimSuffix(key, "/.dir") + "/"
						}
					}
				}
			}

			// Use stored MD5 hash as ETag for S3 compatibility
			etag := string(blob.Properties.Etag)
			if md5Hash, exists := blob.Metadata["s3proxyMD5"]; exists {
				etag = fmt.Sprintf("\"%s\"", md5Hash)
			}

			result.Contents = append(result.Contents, ObjectInfo{
				Key:          key,
				Size:         *blob.Properties.ContentLength,
				ETag:         etag,
				LastModified: blob.Properties.LastModified,
				Metadata:     desanitizeAzureMetadata(blob.Metadata),
			})
		}

		// Add blob prefixes (directories)
		for _, prefix := range resp.Segment.BlobPrefixes {
			result.CommonPrefixes = append(result.CommonPrefixes, prefix.Name)
		}

		result.IsTruncated = resp.NextMarker.NotDone()
		if resp.NextMarker.Val != nil {
			result.NextMarker = *resp.NextMarker.Val
		}
	} else {
		// Flat listing without delimiter
		resp, err := containerURL.ListBlobsFlatSegment(ctx, azMarker, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list blobs: %w", err)
		}

		for _, blob := range resp.Segment.BlobItems {
			key := blob.Name
			// Convert .dir blobs back to directory names
			if strings.HasSuffix(key, "/.dir") {
				// Check if this is a directory marker
				if blob.Metadata != nil {
					if isDir, exists := blob.Metadata["s3proxyDirectoryMarker"]; exists && isDir == "true" {
						if origKey, origExists := blob.Metadata["s3proxyOriginalKey"]; origExists {
							key = origKey
						} else {
							// Fallback: convert .dir suffix back to /
							key = strings.TrimSuffix(key, "/.dir") + "/"
						}
					}
				}
			}

			result.Contents = append(result.Contents, ObjectInfo{
				Key:          key,
				Size:         *blob.Properties.ContentLength,
				ETag:         string(blob.Properties.Etag),
				LastModified: blob.Properties.LastModified,
				Metadata:     desanitizeAzureMetadata(blob.Metadata),
			})
		}

		result.IsTruncated = resp.NextMarker.NotDone()
		if resp.NextMarker.Val != nil {
			result.NextMarker = *resp.NextMarker.Val
		}
	}

	return result, nil
}

func (a *AzureBackend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	containerURL := a.serviceURL.NewContainerURL(bucket)

	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
	}

	blobURL := containerURL.NewBlobURL(normalizedKey)

	// Get properties first for metadata
	props, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get blob properties: %w", err)
	}

	// AGGRESSIVE GET OPTIMIZATION: Tuned strategies for benchmark sizes
	size := props.ContentLength()

	// For files >= 1MB, use optimized reader unless encrypted (buffering corrupts encrypted data)
	if size >= 1024*1024 && !isEncryptedMetadata(props.NewMetadata()) {
		blockBlobURL := containerURL.NewBlockBlobURL(key)

		// Download with minimal retry for speed
		resp, downloadErr := blockBlobURL.Download(ctx, 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})
		if downloadErr != nil {
			return nil, fmt.Errorf("failed to download blob: %w", downloadErr)
		}

		// Use retry reader with minimal retries for speed
		bodyStream := resp.Body(azblob.RetryReaderOptions{
			MaxRetryRequests: 1, // Reduced for speed
		})

		// Use stored MD5 hash as ETag for S3 compatibility
		metadata := desanitizeAzureMetadata(props.NewMetadata())
		etag := string(props.ETag())
		if md5Hash, exists := metadata["s3proxyMD5"]; exists {
			etag = fmt.Sprintf("\"%s\"", md5Hash)
		}

		// Use optimized reader for non-encrypted files only
		body := wrapWithOptimizedReader(bodyStream, size, isEncryptedMetadata(props.NewMetadata()))

		return &Object{
			Body:         body,
			ContentType:  props.ContentType(),
			Size:         size,
			ETag:         etag,
			LastModified: props.LastModified(),
			Metadata:     metadata,
		}, nil
	}

	// For smaller files, use single download with buffering
	resp, err := blobURL.Download(ctx, 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to download blob: %w", err)
	}

	bodyStream := resp.Body(azblob.RetryReaderOptions{
		MaxRetryRequests: 1,
	})

	// Use stored MD5 hash as ETag for S3 compatibility
	metadata := desanitizeAzureMetadata(resp.NewMetadata())
	etag := string(resp.ETag())
	if md5Hash, exists := metadata["s3proxyMD5"]; exists {
		etag = fmt.Sprintf("\"%s\"", md5Hash)
	}

	// Use optimized reader for non-encrypted files only
	body2 := wrapWithFastReader(bodyStream, size, isEncryptedMetadata(resp.NewMetadata()))

	return &Object{
		Body:         body2,
		ContentType:  resp.ContentType(),
		Size:         size,
		ETag:         etag,
		LastModified: resp.LastModified(),
		Metadata:     metadata,
	}, nil
}

// azureHighPerfReader optimizes reading for large files
type azureHighPerfReader struct {
	io.ReadCloser
	size int64
	buf  []byte
	pos  int
	n    int
}

func (r *azureHighPerfReader) Read(p []byte) (n int, err error) {
	// For very large reads (>= 1MB), bypass buffering completely
	if len(p) >= 1024*1024 {
		return r.ReadCloser.Read(p)
	}

	// For medium reads (>= 64KB), use larger buffer
	if len(p) >= 64*1024 {
		if r.buf == nil || len(r.buf) < 512*1024 {
			r.buf = make([]byte, 512*1024) // 512KB buffer for medium reads
		}
	} else {
		// For small reads, use smaller buffer
		if r.buf == nil || len(r.buf) != 64*1024 {
			r.buf = make([]byte, 64*1024) // 64KB buffer for small reads
		}
	}

	// Refill buffer if empty
	if r.pos >= r.n {
		r.n, err = r.ReadCloser.Read(r.buf)
		if r.n == 0 {
			return 0, err
		}
		r.pos = 0
	}

	// Copy from buffer
	n = copy(p, r.buf[r.pos:r.n])
	r.pos += n
	return n, nil
}

// azureFastReader wraps Azure's retry reader with buffering for better performance
type azureFastReader struct {
	io.ReadCloser
	size int64
	buf  []byte
	pos  int
	n    int
}

func (r *azureFastReader) Read(p []byte) (n int, err error) {
	// For large reads, bypass buffering
	if len(p) >= 256*1024 { // 256KB or larger - reduced threshold
		return r.ReadCloser.Read(p)
	}

	// Buffer smaller reads
	if r.buf == nil {
		r.buf = make([]byte, 256*1024) // 256KB buffer - more reasonable size
	}

	// Refill buffer if empty
	if r.pos >= r.n {
		r.n, err = r.ReadCloser.Read(r.buf)
		if r.n == 0 {
			return 0, err
		}
		r.pos = 0
	}

	// Copy from buffer
	n = copy(p, r.buf[r.pos:r.n])
	r.pos += n
	return n, nil
}

// azureFastUploadReader wraps the input reader to buffer small reads
type azureFastUploadReader struct {
	io.Reader
	buf []byte
	pos int
	n   int
	err error
}

func (r *azureFastUploadReader) Read(p []byte) (n int, err error) {
	// For large reads, bypass buffering
	if len(p) >= 1024*1024 { // 1MB or larger
		return r.Reader.Read(p)
	}

	// Buffer smaller reads
	if r.buf == nil {
		r.buf = make([]byte, 1024*1024) // 1MB buffer
	}

	// Fill buffer if empty and no previous EOF
	if r.pos >= r.n {
		if r.err != nil {
			return 0, r.err
		}
		r.n, r.err = r.Reader.Read(r.buf)
		r.pos = 0
		if r.n == 0 {
			return 0, r.err
		}
	}

	// Copy from buffer
	if r.pos < r.n {
		n = copy(p, r.buf[r.pos:r.n])
		r.pos += n
		return n, nil
	}

	return 0, r.err
}

// Known metadata key mappings for encryption
var azureMetadataMapping = map[string]string{
	"x-amz-meta-encryption-algorithm": "xamzmetaencryptionalgorithm",
	"x-amz-meta-encryption-key-id":    "xamzmetaencryptionkeyid",
	"x-amz-meta-encryption-dek":       "xamzmetaencryptiondek",
	"x-amz-meta-encryption-nonce":     "xamzmetaencryptionnonce",
	"x-amz-meta-encrypted-size":       "xamzmetaencryptedsize",
	"x-amz-server-side-encryption":    "xamzserversideencryption",
	"x-encryption-key":                "xencryptionkey",
	"x-encryption-algorithm":          "xencryptionalgorithm",
	"timestamp":                       "timestamp",
	"test":                            "test",
	"s3proxymd5":                      "s3proxyMD5",
	"s3proxydirectorymarker":          "s3proxyDirectoryMarker",
	"s3proxyoriginalkey":              "s3proxyOriginalKey",
	"content-type":                    "contenttype",
}

// Reverse mapping for reading metadata
var azureMetadataReverseMapping = map[string]string{
	"xamzmetaencryptionalgorithm": "x-amz-meta-encryption-algorithm",
	"xamzmetaencryptionkeyid":     "x-amz-meta-encryption-key-id",
	"xamzmetaencryptiondek":       "x-amz-meta-encryption-dek",
	"xamzmetaencryptionnonce":     "x-amz-meta-encryption-nonce",
	"xamzmetaencryptedsize":       "x-amz-meta-encrypted-size",
	"xamzserversideencryption":    "x-amz-server-side-encryption",
	"xencryptionkey":              "x-encryption-key",
	"xencryptionalgorithm":        "x-encryption-algorithm",
	"s3proxymd5":                  "s3proxyMD5",
	"s3proxydirectorymarker":      "s3proxyDirectoryMarker",
	"contenttype":                 "content-type",
	"s3proxyoriginalkey":          "s3proxyOriginalKey",
}

// sanitizeAzureMetadata converts metadata keys to Azure-compatible format
func sanitizeAzureMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return make(map[string]string)
	}

	sanitized := make(map[string]string, len(metadata))
	for k, v := range metadata {
		// Check if we have a known mapping
		if mappedKey, exists := azureMetadataMapping[strings.ToLower(k)]; exists {
			sanitized[mappedKey] = v
			continue
		}

		// Otherwise, sanitize the key
		sanitizedKey := ""
		for i, ch := range k {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
				sanitizedKey += string(ch)
			} else if ch >= '0' && ch <= '9' {
				if i > 0 {
					sanitizedKey += string(ch)
				}
			}
			// Skip special characters
		}

		// Ensure key starts with a letter
		if sanitizedKey != "" {
			if sanitizedKey[0] >= '0' && sanitizedKey[0] <= '9' {
				sanitizedKey = "x" + sanitizedKey
			}
			sanitized[sanitizedKey] = v
		}
	}
	return sanitized
}

// desanitizeAzureMetadata converts Azure metadata keys back to original format
func desanitizeAzureMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	desanitized := make(map[string]string, len(metadata))
	for k, v := range metadata {
		// Check if we have a reverse mapping
		if originalKey, exists := azureMetadataReverseMapping[strings.ToLower(k)]; exists {
			desanitized[originalKey] = v
		} else {
			// Keep as-is for unknown keys
			desanitized[k] = v
		}
	}
	return desanitized
}

func (a *AzureBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	containerURL := a.serviceURL.NewContainerURL(bucket)

	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
		"size":   size,
	}).Info("Azure PutObject called")

	// Sanitize metadata for Azure
	// logrus.WithField("originalMetadata", metadata).Debug("Before sanitization")
	metadata = sanitizeAzureMetadata(metadata)
	// logrus.WithField("sanitizedMetadata", metadata).Debug("After sanitization")

	// Handle directory-like objects (keys ending with /)
	// Azure doesn't allow blob names ending with /, so normalize them
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		logrus.WithField("key", key).Info("Converting directory-like object to .dir marker")

		// For S3A compatibility: when creating a directory marker, we need to ensure
		// there's no conflicting file at the path without trailing slash
		baseKey := strings.TrimSuffix(key, "/")
		baseBlobURL := containerURL.NewBlobURL(baseKey)

		// Check if there's a conflicting file and delete it if it exists
		_, err := baseBlobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
		if err == nil {
			logrus.WithField("conflictingKey", baseKey).Info("Found conflicting file - deleting to allow directory creation")
			_, deleteErr := baseBlobURL.Delete(ctx, azblob.DeleteSnapshotsOptionInclude, azblob.BlobAccessConditions{})
			if deleteErr != nil {
				logrus.WithError(deleteErr).WithField("key", baseKey).Warn("Failed to delete conflicting file")
			}
		}

		// For directory markers, create a special blob without the trailing slash
		// and add metadata to indicate it's a directory marker
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
		metadata["s3proxyDirectoryMarker"] = "true"
		metadata["s3proxyOriginalKey"] = key
		// For empty directory markers, always use MD5 of empty string
		metadata["s3proxyMD5"] = "d41d8cd98f00b204e9800998ecf8427e"

		logrus.WithFields(logrus.Fields{
			"originalKey":   key,
			"normalizedKey": normalizedKey,
		}).Info("Directory marker will be stored")
	}

	blobURL := containerURL.NewBlockBlobURL(normalizedKey)

	// AGGRESSIVE PUT OPTIMIZATION: Maximum performance approach
	if size < 256*1024 { // < 256KB: Single shot upload
		// For small files, check if already buffered
		var data []byte
		if br, ok := reader.(*bytes.Reader); ok {
			// Already buffered, reuse
			data = make([]byte, size)
			_, _ = br.Read(data)
			_, _ = br.Seek(0, 0) // Reset for potential retry
		} else {
			// Read into memory
			data = a.bufferPool.Get().([]byte)
			if len(data) < int(size) {
				a.bufferPool.Put(&data)
				data = make([]byte, size)
			} else {
				data = data[:size]
				defer a.bufferPool.Put(&data)
			}

			_, err := io.ReadFull(reader, data)
			if err != nil {
				return fmt.Errorf("failed to read data: %w", err)
			}
		}

		// Calculate MD5 hash for S3 compatibility
		hash := md5.Sum(data) //nolint:gosec // MD5 is required for Azure ETag compatibility
		metadata["s3proxyMD5"] = hex.EncodeToString(hash[:])

		// Fast upload with minimal overhead
		httpHeaders := azblob.BlobHTTPHeaders{
			ContentType: "application/octet-stream",
		}

		_, err := blobURL.Upload(ctx, bytes.NewReader(data), httpHeaders,
			azblob.Metadata(metadata), azblob.BlobAccessConditions{},
			azblob.DefaultAccessTier, nil, azblob.ClientProvidedKeyOptions{},
			azblob.ImmutabilityPolicyOptions{})
		if err != nil {
			return fmt.Errorf("failed to upload blob: %w", err)
		}
		return nil
	}

	// For larger files, we can't easily calculate MD5 without reading the entire content
	// For now, generate a deterministic ETag based on size and timestamp
	// This is not ideal but maintains compatibility for large files
	if _, exists := metadata["s3proxyMD5"]; !exists {
		metadata["s3proxyMD5"] = fmt.Sprintf("large-file-%d-%d", size, time.Now().Unix())
	}

	// ULTRA-HIGH PERFORMANCE STREAMING
	// Direct reader without extra buffering layer for maximum speed

	// AGGRESSIVE: Optimized buffer sizes for each benchmark
	var bufferSize int
	var maxBuffers int

	if size >= 8*1024*1024 && size <= 12*1024*1024 { // 10MB: EXTREME PERFORMANCE
		// Special optimization for 10MB benchmark
		bufferSize = 2 * 1024 * 1024 // 2MB buffers
		maxBuffers = 16              // 16 concurrent = 32MB in flight
		// Use direct reader for maximum speed
		_, err := azblob.UploadStreamToBlockBlob(ctx, reader, blobURL, azblob.UploadStreamToBlockBlobOptions{
			BufferSize: bufferSize,
			MaxBuffers: maxBuffers,
			Metadata:   azblob.Metadata(metadata),
			BlobHTTPHeaders: azblob.BlobHTTPHeaders{
				ContentType: "application/octet-stream",
			},
		})
		if err != nil {
			return fmt.Errorf("failed to upload blob: %w", err)
		}
		return nil
	} else if size >= 1024*1024 { // >= 1MB: HIGH PERFORMANCE
		// Optimized for 1MB benchmark
		bufferSize = 512 * 1024 // 512KB buffers
		maxBuffers = 8          // 8 concurrent = 4MB in flight
	} else { // 256KB - 1MB: MODERATE
		bufferSize = 256 * 1024 // 256KB buffers
		maxBuffers = 4          // 4 concurrent = 1MB in flight
	}

	// Use buffered reader for non-10MB files
	bufferedReader := &azureFastUploadReader{Reader: reader}

	_, err := azblob.UploadStreamToBlockBlob(ctx, bufferedReader, blobURL, azblob.UploadStreamToBlockBlobOptions{
		BufferSize: bufferSize,
		MaxBuffers: maxBuffers,
		Metadata:   azblob.Metadata(metadata),
		BlobHTTPHeaders: azblob.BlobHTTPHeaders{
			ContentType: "application/octet-stream",
		},
	})
	if err != nil {
		return fmt.Errorf("failed to upload blob: %w", err)
	}

	return nil
}

func (a *AzureBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	containerURL := a.serviceURL.NewContainerURL(bucket)

	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
	}

	blobURL := containerURL.NewBlobURL(normalizedKey)

	_, err := blobURL.Delete(ctx, azblob.DeleteSnapshotsOptionInclude, azblob.BlobAccessConditions{})
	if err != nil {
		return fmt.Errorf("failed to delete blob: %w", err)
	}

	return nil
}

func (a *AzureBackend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	containerURL := a.serviceURL.NewContainerURL(bucket)

	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Info("Azure HeadObject called")

	// For S3A compatibility: if the key doesn't end with /, check for actual file first
	// If no file exists but there's a directory marker, return 404 to allow directory creation
	if !strings.HasSuffix(key, "/") {
		logrus.WithField("key", key).Info("Checking for actual file (non-slash key)")

		// Check for actual file
		blobURL := containerURL.NewBlobURL(key)
		props, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
		if err == nil {
			logrus.WithField("key", key).Info("Found actual file - checking if it's a directory marker")

			// Found actual file - check if it's a directory marker
			metadata := props.NewMetadata()
			if isDir, exists := metadata["s3proxyDirectoryMarker"]; exists && isDir == "true" {
				logrus.WithField("key", key).Info("Found s3proxy directory marker without .dir suffix - returning 404")
				// This is a directory marker stored without .dir suffix, which shouldn't happen
				// but if it does, we should return 404 to allow S3A to create proper directory
				return nil, fmt.Errorf("object not found")
			}

			// Check for Azure HDI (Hierarchical Data Interface) folder markers
			// Note: Azure metadata keys can have different casing
			if hdiFolder, exists := metadata["hdi_isfolder"]; exists && hdiFolder == "true" {
				logrus.WithField("key", key).Info("Found Azure HDI folder marker (lowercase) - returning 404 for S3A compatibility")
				// Azure created this as a folder marker, treat it as directory for S3A compatibility
				return nil, fmt.Errorf("object not found")
			}
			if hdiFolder, exists := metadata["Hdi_isfolder"]; exists && hdiFolder == "true" {
				logrus.WithField("key", key).Info("Found Azure HDI folder marker (capitalized) - returning 404 for S3A compatibility")
				// Azure created this as a folder marker, treat it as directory for S3A compatibility
				return nil, fmt.Errorf("object not found")
			}

			// Use stored MD5 hash as ETag for S3 compatibility
			etag := string(props.ETag())
			if md5Hash, exists := metadata["s3proxyMD5"]; exists {
				etag = fmt.Sprintf("\"%s\"", md5Hash)
			}

			logrus.WithFields(logrus.Fields{
				"key":  key,
				"size": props.ContentLength(),
				"etag": etag,
			}).Info("Returning actual file info")

			return &ObjectInfo{
				Key:          key,
				Size:         props.ContentLength(),
				ETag:         etag,
				LastModified: props.LastModified(),
				Metadata:     desanitizeAzureMetadata(metadata),
			}, nil
		}

		logrus.WithField("key", key).Info("No actual file found - checking for directory marker")

		// No actual file found, check if there's a directory marker
		dirMarkerKey := key + "/.dir"
		dirBlobURL := containerURL.NewBlobURL(dirMarkerKey)
		_, dirErr := dirBlobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
		if dirErr == nil {
			logrus.WithField("key", key).Info("Directory marker exists - returning 404 to allow S3A directory creation")
			// Directory marker exists, return 404 for the file path to allow S3A directory creation
			return nil, fmt.Errorf("object not found")
		}

		logrus.WithField("key", key).Info("Neither file nor directory marker found - returning 404")
		// Neither file nor directory marker found - return original error
		return nil, fmt.Errorf("failed to get blob properties: %w", err)
	}

	// Handle directory-like objects (keys ending with /)
	normalizedKey := strings.TrimSuffix(key, "/") + "/.dir"
	blobURL := containerURL.NewBlobURL(normalizedKey)

	props, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get blob properties: %w", err)
	}

	// If this was a directory marker, restore the original key
	resultKey := key
	metadata := props.NewMetadata()
	if isDir, exists := metadata["s3proxyDirectoryMarker"]; exists && isDir == "true" {
		if origKey, origExists := metadata["s3proxyOriginalKey"]; origExists {
			resultKey = origKey
		}
	}

	// Use stored MD5 hash as ETag for S3 compatibility
	etag := string(props.ETag())
	if md5Hash, exists := metadata["s3proxyMD5"]; exists {
		etag = fmt.Sprintf("\"%s\"", md5Hash)
	}

	return &ObjectInfo{
		Key:          resultKey,
		Size:         props.ContentLength(),
		ETag:         etag,
		LastModified: props.LastModified(),
		Metadata:     desanitizeAzureMetadata(metadata),
	}, nil
}

func (a *AzureBackend) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	// Azure doesn't have per-object ACLs like S3
	// Return a default ACL
	return &ACL{
		Owner: Owner{
			ID:          a.accountName,
			DisplayName: a.accountName,
		},
		Grants: []Grant{
			{
				Grantee: Grantee{
					Type:        "CanonicalUser",
					ID:          a.accountName,
					DisplayName: a.accountName,
				},
				Permission: "FULL_CONTROL",
			},
		},
	}, nil
}

func (a *AzureBackend) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	// Azure doesn't support per-object ACLs
	// Log and ignore
	// logrus.Debug("PutObjectACL not supported for Azure backend")
	return nil
}

func (a *AzureBackend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	// Azure doesn't have the same multipart upload concept as S3
	// Generate a unique upload ID
	uploadID := fmt.Sprintf("%s-%d", key, time.Now().UnixNano())
	return uploadID, nil
}

func (a *AzureBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	containerURL := a.serviceURL.NewContainerURL(bucket)
	blobURL := containerURL.NewBlockBlobURL(key)

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read part data: %w", err)
	}

	blockID := fmt.Sprintf("%05d", partNumber)
	_, err = blobURL.StageBlock(ctx, blockID, bytes.NewReader(data), azblob.LeaseAccessConditions{}, nil, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to stage block: %w", err)
	}

	return fmt.Sprintf("\"%s\"", blockID), nil
}

func (a *AzureBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	containerURL := a.serviceURL.NewContainerURL(bucket)
	blobURL := containerURL.NewBlockBlobURL(key)

	blockList := make([]string, len(parts))
	for i, part := range parts {
		blockList[i] = fmt.Sprintf("%05d", part.PartNumber)
	}

	_, err := blobURL.CommitBlockList(ctx, blockList, azblob.BlobHTTPHeaders{}, azblob.Metadata{}, azblob.BlobAccessConditions{}, azblob.AccessTierNone, nil, azblob.ClientProvidedKeyOptions{}, azblob.ImmutabilityPolicyOptions{})
	if err != nil {
		return fmt.Errorf("failed to commit block list: %w", err)
	}

	return nil
}

func (a *AzureBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	// No specific action needed for Azure
	// logrus.Debug("AbortMultipartUpload called for Azure backend")
	return nil
}

func (a *AzureBackend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	containerURL := a.serviceURL.NewContainerURL(bucket)
	blobURL := containerURL.NewBlockBlobURL(key)

	resp, err := blobURL.GetBlockList(ctx, azblob.BlockListUncommitted, azblob.LeaseAccessConditions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get block list: %w", err)
	}

	result := &ListPartsResult{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
		Parts:    make([]Part, 0),
	}

	for i, block := range resp.UncommittedBlocks {
		if i+1 > partNumberMarker && len(result.Parts) < maxParts {
			result.Parts = append(result.Parts, Part{
				PartNumber: i + 1,
				Size:       block.Size,
				ETag:       block.Name,
			})
		}
	}

	result.IsTruncated = len(resp.UncommittedBlocks) > partNumberMarker+maxParts
	if result.IsTruncated {
		result.NextPartNumberMarker = partNumberMarker + len(result.Parts)
	}

	return result, nil
}

// isEncryptedMetadata checks if the metadata indicates an encrypted object
func isEncryptedMetadata(metadata map[string]string) bool {
	return metadata["xamzmetaencryptionalgorithm"] != ""
}

// wrapWithOptimizedReader wraps the stream with high-performance reader for large files, unless encrypted
func wrapWithOptimizedReader(stream io.ReadCloser, size int64, isEncrypted bool) io.ReadCloser {
	if isEncrypted {
		return stream // No optimization for encrypted data to prevent corruption
	}
	return &azureHighPerfReader{ReadCloser: stream, size: size}
}

// wrapWithFastReader wraps the stream with fast reader for smaller files, unless encrypted
func wrapWithFastReader(stream io.ReadCloser, size int64, isEncrypted bool) io.ReadCloser {
	if isEncrypted {
		return stream // No optimization for encrypted data to prevent corruption
	}
	return &azureFastReader{ReadCloser: stream, size: size}
}
