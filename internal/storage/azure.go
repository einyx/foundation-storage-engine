// Package storage provides storage backend implementations for Azure Blob Storage.
package storage

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // MD5 is required for Azure ETag compatibility
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

type AzureBackend struct {
	client        *azblob.Client
	accountName   string
	containerName string
	bufferPool    sync.Pool
	// Track multipart upload metadata
	uploadMetadata sync.Map // uploadID -> metadata map[string]string
	// Limit concurrent operations to prevent resource exhaustion
	uploadSem chan struct{}
}

func NewAzureBackend(cfg *config.AzureStorageConfig) (*AzureBackend, error) {
	var client *azblob.Client
	var err error

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)
	}

	// Create client options with custom retry policy
	clientOptions := &azblob.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Retry: policy.RetryOptions{
				MaxRetries:    0,                      // No retries - let our wrapper handle it
				TryTimeout:    60 * time.Second,       // 1 minute timeout per request
				RetryDelay:    100 * time.Millisecond, // Minimal delay
				MaxRetryDelay: 1 * time.Second,        // Small max delay
			},
			Transport: &http.Client{
				Timeout: 60 * time.Second,
				Transport: &http.Transport{
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   10,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					DisableKeepAlives:     false, // Keep connections alive
					DisableCompression:    true,  // Disable compression for speed
				},
			},
		},
	}

	// Handle authentication
	if cfg.UseSAS && cfg.SASToken != "" {
		// SAS token authentication
		if !strings.Contains(endpoint, "?") {
			endpoint += "?" + cfg.SASToken
		} else {
			endpoint += "&" + cfg.SASToken
		}
		client, err = azblob.NewClientWithNoCredential(endpoint, clientOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create SAS client: %w", err)
		}
	} else if cfg.UseSAS {
		// Anonymous access
		client, err = azblob.NewClientWithNoCredential(endpoint, clientOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create anonymous client: %w", err)
		}
	} else {
		// Shared key authentication
		cred, err := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials: %w", err)
		}
		client, err = azblob.NewClientWithSharedKeyCredential(endpoint, cred, clientOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
	}

	containerName := cfg.ContainerName
	if containerName == "" {
		containerName = "$root"
	}

	return &AzureBackend{
		client:        client,
		accountName:   cfg.AccountName,
		containerName: containerName,
		bufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 1024*1024) // 1MB buffers
				return &buf
			},
		},
		uploadSem: make(chan struct{}, 4), // Limit concurrent uploads to prevent overwhelming Azure
	}, nil
}

// normalizeAzureContainerName converts S3 bucket names to valid Azure container names
// Azure container names must:
// - Be 3-63 characters long
// - Start with a letter or number
// - Contain only lowercase letters, numbers, and hyphens
// - Not contain consecutive hyphens
// - Not end with a hyphen
func normalizeAzureContainerName(s3BucketName string) string {
	// Convert to lowercase
	name := strings.ToLower(s3BucketName)
	
	// Replace underscores with hyphens
	name = strings.ReplaceAll(name, "_", "-")
	
	// Replace dots with hyphens (dots are not allowed in Azure container names)
	name = strings.ReplaceAll(name, ".", "-")
	
	// Remove any other invalid characters
	var result []rune
	lastWasHyphen := false
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			result = append(result, ch)
			lastWasHyphen = false
		} else if ch == '-' && !lastWasHyphen && len(result) > 0 {
			result = append(result, ch)
			lastWasHyphen = true
		}
	}
	
	// Ensure it doesn't end with hyphen
	normalized := strings.TrimSuffix(string(result), "-")
	
	// Ensure minimum length
	if len(normalized) < 3 {
		normalized = "s3-" + normalized
	}
	
	// Ensure maximum length
	if len(normalized) > 63 {
		normalized = normalized[:63]
		// Remove trailing hyphen if truncation created one
		normalized = strings.TrimSuffix(normalized, "-")
	}
	
	// If name starts with number, prefix with 's3-'
	if len(normalized) > 0 && normalized[0] >= '0' && normalized[0] <= '9' {
		normalized = "s3-" + normalized
		if len(normalized) > 63 {
			normalized = normalized[:63]
		}
	}
	
	// Log normalization if changed
	if normalized != s3BucketName {
		logrus.WithFields(logrus.Fields{
			"original": s3BucketName,
			"normalized": normalized,
		}).Debug("Normalized container name for Azure")
	}
	
	return normalized
}

// isValidAzureContainerName checks if a name is valid for Azure container
func isValidAzureContainerName(name string) bool {
	// Must be 3-63 characters
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	
	// Must start with lowercase letter or number
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= '0' && name[0] <= '9')) {
		return false
	}
	
	// Check all characters and no consecutive hyphens
	lastWasHyphen := false
	for i, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			lastWasHyphen = false
		} else if ch == '-' {
			// No consecutive hyphens
			if lastWasHyphen {
				return false
			}
			// No hyphen at the end
			if i == len(name)-1 {
				return false
			}
			lastWasHyphen = true
		} else {
			// Invalid character (including underscore)
			return false
		}
	}
	
	return true
}

func (a *AzureBackend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	var buckets []BucketInfo

	pager := a.client.NewListContainersPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}

		for _, container := range page.ContainerItems {
			buckets = append(buckets, BucketInfo{
				Name:         *container.Name,
				CreationDate: *container.Properties.LastModified,
			})
		}
	}

	return buckets, nil
}

func (a *AzureBackend) CreateBucket(ctx context.Context, bucket string) error {
	_, err := a.client.CreateContainer(ctx, bucket, &container.CreateOptions{
		Access: nil, // Private access
	})
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	return nil
}

func (a *AzureBackend) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := a.client.DeleteContainer(ctx, bucket, nil)
	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}
	return nil
}

func (a *AzureBackend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	_, err := a.client.ServiceClient().NewContainerClient(bucket).GetProperties(ctx, nil)
	if err != nil {
		// Check if it's a 404 error
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Metadata key mapping for Azure compatibility
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
func desanitizeAzureMetadata(metadata map[string]*string) map[string]string {
	if metadata == nil {
		return nil
	}

	desanitized := make(map[string]string, len(metadata))
	for k, v := range metadata {
		if v == nil {
			continue
		}
		// Check if we have a reverse mapping
		if originalKey, exists := azureMetadataReverseMapping[strings.ToLower(k)]; exists {
			desanitized[originalKey] = *v
		} else {
			// Keep as-is for unknown keys
			desanitized[k] = *v
		}
	}
	return desanitized
}

// convertMetadataToPointers converts string map to pointer map for Azure SDK
func convertMetadataToPointers(metadata map[string]string) map[string]*string {
	if metadata == nil {
		return nil
	}
	result := make(map[string]*string, len(metadata))
	for k, v := range metadata {
		vCopy := v
		result[k] = &vCopy
	}
	return result
}

// isEncryptedMetadata checks if the metadata indicates an encrypted object
func isEncryptedMetadata(metadata map[string]string) bool {
	return metadata["xamzmetaencryptionalgorithm"] != ""
}

// isBase64 checks if a string is a valid base64-encoded string
func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func (a *AzureBackend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	return a.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, "", maxKeys)
}

func (a *AzureBackend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	result := &ListObjectsResult{
		CommonPrefixes: []string{},
		Contents:       []ObjectInfo{},
	}

	containerClient := a.client.ServiceClient().NewContainerClient(bucket)
	
	opts := &container.ListBlobsHierarchyOptions{
		Prefix: &prefix,
		MaxResults: func() *int32 { 
			mk := int32(maxKeys)
			return &mk 
		}(),
	}
	
	if marker != "" {
		opts.Marker = &marker
	}

	if delimiter != "" {
		// Use hierarchical listing
		pager := containerClient.NewListBlobsHierarchyPager(delimiter, opts)
		
		pageCount := 0
		for pager.More() && len(result.Contents) < maxKeys {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list blobs: %w", err)
			}
			pageCount++
			
			// Safety check: prevent infinite loops
			if pageCount > 100 && len(page.Segment.BlobItems) == 0 && len(page.Segment.BlobPrefixes) == 0 {
				logrus.WithFields(logrus.Fields{
					"bucket": bucket,
					"prefix": prefix,
					"pageCount": pageCount,
				}).Warn("Breaking potential infinite loop in Azure blob listing")
				break
			}

			// Process blobs
			for _, blob := range page.Segment.BlobItems {
				if len(result.Contents) >= maxKeys {
					result.IsTruncated = true
					break
				}

				key := *blob.Name
				// Convert .dir blobs back to directory names
				if strings.HasSuffix(key, "/.dir") && blob.Metadata != nil {
					if isDir, exists := blob.Metadata["s3proxyDirectoryMarker"]; exists && isDir != nil && *isDir == "true" {
						if origKey, exists := blob.Metadata["s3proxyOriginalKey"]; exists && origKey != nil {
							key = *origKey
						} else {
							key = strings.TrimSuffix(key, "/.dir") + "/"
						}
					}
				}

				etag := string(*blob.Properties.ETag)
				if blob.Metadata != nil {
					if md5Hash, exists := blob.Metadata["s3proxyMD5"]; exists && md5Hash != nil {
						etag = fmt.Sprintf("\"%s\"", *md5Hash)
					}
				}

				result.Contents = append(result.Contents, ObjectInfo{
					Key:          key,
					Size:         *blob.Properties.ContentLength,
					ETag:         etag,
					LastModified: *blob.Properties.LastModified,
					Metadata:     desanitizeAzureMetadata(blob.Metadata),
				})
			}

			// Process prefixes (directories)
			for _, prefix := range page.Segment.BlobPrefixes {
				result.CommonPrefixes = append(result.CommonPrefixes, *prefix.Name)
			}

			if page.NextMarker != nil && *page.NextMarker != "" {
				// Only set IsTruncated if we actually have results or hit the max limit
				// Azure can return NextMarker even when there are no more items
				if len(result.Contents) > 0 || len(result.CommonPrefixes) > 0 || len(result.Contents) >= maxKeys {
					result.NextMarker = *page.NextMarker
					result.IsTruncated = true
				}
			}
		}
	} else {
		// Flat listing
		opts := &container.ListBlobsFlatOptions{
			Prefix: &prefix,
			Marker: &marker,
			MaxResults: func() *int32 { 
				mk := int32(maxKeys)
				return &mk 
			}(),
		}

		pager := containerClient.NewListBlobsFlatPager(opts)
		
		pageCount := 0
		for pager.More() && len(result.Contents) < maxKeys {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list blobs: %w", err)
			}
			pageCount++
			
			// Safety check: prevent infinite loops
			if pageCount > 100 && len(page.Segment.BlobItems) == 0 {
				logrus.WithFields(logrus.Fields{
					"bucket": bucket,
					"prefix": prefix,
					"pageCount": pageCount,
				}).Warn("Breaking potential infinite loop in Azure blob listing")
				break
			}

			for _, blob := range page.Segment.BlobItems {
				if len(result.Contents) >= maxKeys {
					result.IsTruncated = true
					break
				}

				key := *blob.Name
				// Convert .dir blobs back to directory names
				if strings.HasSuffix(key, "/.dir") && blob.Metadata != nil {
					if isDir, exists := blob.Metadata["s3proxyDirectoryMarker"]; exists && isDir != nil && *isDir == "true" {
						if origKey, exists := blob.Metadata["s3proxyOriginalKey"]; exists && origKey != nil {
							key = *origKey
						} else {
							key = strings.TrimSuffix(key, "/.dir") + "/"
						}
					}
				}

				result.Contents = append(result.Contents, ObjectInfo{
					Key:          key,
					Size:         *blob.Properties.ContentLength,
					ETag:         string(*blob.Properties.ETag),
					LastModified: *blob.Properties.LastModified,
					Metadata:     desanitizeAzureMetadata(blob.Metadata),
				})
			}

			if page.NextMarker != nil && *page.NextMarker != "" {
				// Only set IsTruncated if we actually have results or hit the max limit
				// Azure can return NextMarker even when there are no more items
				if len(result.Contents) > 0 || len(result.CommonPrefixes) > 0 || len(result.Contents) >= maxKeys {
					result.NextMarker = *page.NextMarker
					result.IsTruncated = true
				}
			}
		}
	}

	return result, nil
}

func (a *AzureBackend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	// Validate container name for Azure
	if !isValidAzureContainerName(bucket) {
		return nil, fmt.Errorf("invalid container name '%s' for Azure: must be 3-63 chars, lowercase letters/numbers/hyphens only, no underscores", bucket)
	}
	
	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
	}

	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlobClient(normalizedKey)
	
	// Get properties first
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob properties: %w", err)
	}

	// Download the blob
	downloadResponse, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to download blob: %w", err)
	}

	// Get metadata
	metadata := make(map[string]string)
	if props.Metadata != nil {
		metadata = desanitizeAzureMetadata(props.Metadata)
	}

	// Use stored MD5 hash as ETag for S3 compatibility
	etag := string(*props.ETag)
	if md5Hash, exists := metadata["s3proxyMD5"]; exists {
		etag = fmt.Sprintf("\"%s\"", md5Hash)
	}

	return &Object{
		Body:         downloadResponse.Body,
		ContentType:  *props.ContentType,
		Size:         *props.ContentLength,
		ETag:         etag,
		LastModified: *props.LastModified,
		Metadata:     metadata,
	}, nil
}

func (a *AzureBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	// Validate container name for Azure
	if !isValidAzureContainerName(bucket) {
		return fmt.Errorf("invalid container name '%s' for Azure: must be 3-63 chars, lowercase letters/numbers/hyphens only, no underscores", bucket)
	}
	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
		"size":   size,
	}).Info("Azure PutObject called")

	// Sanitize metadata for Azure
	metadata = sanitizeAzureMetadata(metadata)

	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		// For directory markers, create a special blob
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
		metadata["s3proxyDirectoryMarker"] = "true"
		metadata["s3proxyOriginalKey"] = key
		metadata["s3proxyMD5"] = "d41d8cd98f00b204e9800998ecf8427e" // MD5 of empty string
	}

	// For small files, calculate MD5
	if size < 256*1024 { // < 256KB
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("failed to read data: %w", err)
		}
		
		// Calculate MD5
		hash := md5.Sum(data)
		md5Hash := hex.EncodeToString(hash[:])
		metadata["s3proxyMD5"] = md5Hash
		
		reader = bytes.NewReader(data)
	}

	// Upload options
	uploadOptions := &azblob.UploadStreamOptions{
		Metadata: convertMetadataToPointers(metadata),
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: func() *string {
				ct := "application/octet-stream"
				if contentType, ok := metadata["Content-Type"]; ok {
					ct = contentType
				}
				return &ct
			}(),
		},
	}

	// Upload the blob
	_, err := a.client.UploadStream(ctx, bucket, normalizedKey, reader, uploadOptions)
	if err != nil {
		return fmt.Errorf("failed to upload blob: %w", err)
	}

	return nil
}

func (a *AzureBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
	}

	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlobClient(normalizedKey)
	
	_, err := blobClient.Delete(ctx, nil)
	if err != nil {
		// Check if it's a 404 error - S3 returns success for non-existent objects
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("failed to delete blob: %w", err)
	}

	return nil
}

func (a *AzureBackend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + "/.dir"
	}

	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlobClient(normalizedKey)
	
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob properties: %w", err)
	}

	// Get metadata
	metadata := make(map[string]string)
	if props.Metadata != nil {
		metadata = desanitizeAzureMetadata(props.Metadata)
	}

	// Use stored MD5 hash as ETag for S3 compatibility
	etag := string(*props.ETag)
	if md5Hash, exists := metadata["s3proxyMD5"]; exists {
		etag = fmt.Sprintf("\"%s\"", md5Hash)
	}

	return &ObjectInfo{
		Key:          key,
		Size:         *props.ContentLength,
		ETag:         etag,
		LastModified: *props.LastModified,
		Metadata:     metadata,
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
	// This is a no-op for S3 compatibility
	return nil
}

func (a *AzureBackend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	// Generate a unique upload ID
	uploadID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), key)
	
	// Store metadata for later use
	a.uploadMetadata.Store(uploadID, metadata)
	
	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Initiated multipart upload for Azure")
	
	return uploadID, nil
}

func (a *AzureBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	startTime := time.Now()
	
	// Acquire semaphore
	semAcquireStart := time.Now()
	select {
	case a.uploadSem <- struct{}{}:
		defer func() { <-a.uploadSem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	semAcquireTime := time.Since(semAcquireStart)
	
	logrus.WithFields(logrus.Fields{
		"bucket":          bucket,
		"key":             key,
		"uploadID":        uploadID,
		"partNumber":      partNumber,
		"size":            size,
		"sizeMB":          float64(size) / (1024 * 1024),
		"semAcquireTime":  semAcquireTime,
	}).Info("Azure UploadPart called")

	// Azure requires block IDs to be base64-encoded and of equal length
	blockID := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%010d", partNumber)))
	
	logrus.WithFields(logrus.Fields{
		"partNumber": partNumber,
		"blockID": blockID,
		"blockIDLen": len(blockID),
	}).Debug("Generated block ID for Azure")

	// Get block blob client
	blockBlobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlockBlobClient(key)

	// For parts larger than 30MB, split into smaller blocks to avoid timeouts
	const maxBlockSize = 30 * 1024 * 1024 // 30MB max per block
	
	if size > maxBlockSize {
		// Upload in multiple blocks for this part
		logrus.WithFields(logrus.Fields{
			"partNumber": partNumber,
			"partSize":   size,
			"blocks":     (size + maxBlockSize - 1) / maxBlockSize,
		}).Info("Large part detected, splitting into multiple blocks")
		
		// We need to handle this differently - stage multiple blocks for this part
		blockNum := 0
		totalRead := int64(0)
		
		for totalRead < size {
			blockSize := size - totalRead
			if blockSize > maxBlockSize {
				blockSize = maxBlockSize
			}
			
			// Read this block
			blockData := make([]byte, blockSize)
			n, err := io.ReadFull(reader, blockData)
			if err != nil && err != io.EOF {
				return "", fmt.Errorf("failed to read block %d: %w", blockNum, err)
			}
			if int64(n) != blockSize {
				return "", fmt.Errorf("incomplete read for block %d: got %d, expected %d", blockNum, n, blockSize)
			}
			
			// Generate unique block ID for this sub-block
			subBlockID := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%010d-%03d", partNumber, blockNum)))
			
			// Stage this sub-block
			_, err = blockBlobClient.StageBlock(ctx, subBlockID, streaming.NopCloser(bytes.NewReader(blockData)), nil)
			if err != nil {
				return "", fmt.Errorf("failed to stage sub-block %d: %w", blockNum, err)
			}
			
			totalRead += blockSize
			blockNum++
			
			logrus.WithFields(logrus.Fields{
				"partNumber": partNumber,
				"blockNum":   blockNum,
				"blockSize":  blockSize,
				"progress":   fmt.Sprintf("%d/%d", totalRead, size),
			}).Debug("Staged sub-block for large part")
		}
		
		// Return a composite block ID that represents all sub-blocks
		return blockID, nil
	}
	
	// For smaller parts, use the original buffering approach
	buffer := make([]byte, size)
	n, err := io.ReadFull(reader, buffer)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read part data: %w", err)
	}
	if int64(n) != size {
		return "", fmt.Errorf("incomplete read: got %d bytes, expected %d", n, size)
	}
	
	body := streaming.NopCloser(bytes.NewReader(buffer))

	// Stage the block
	stageStart := time.Now()
	_, err = blockBlobClient.StageBlock(ctx, blockID, body, nil)
	stageTime := time.Since(stageStart)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error":     err.Error(),
			"stageTime": stageTime,
		}).Error("Failed to stage block")
		return "", fmt.Errorf("failed to stage block: %w", err)
	}

	totalTime := time.Since(startTime)
	throughputMBps := (float64(size) / (1024 * 1024)) / stageTime.Seconds()
	
	logrus.WithFields(logrus.Fields{
		"blockID":        blockID,
		"partNumber":     partNumber,
		"size":           size,
		"stageTime":      stageTime,
		"totalTime":      totalTime,
		"throughputMBps": fmt.Sprintf("%.2f", throughputMBps),
	}).Info("Successfully staged block")

	// Return the block ID as ETag for S3 compatibility
	return fmt.Sprintf("\"%s\"", blockID), nil
}

func (a *AzureBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
		"parts":    len(parts),
	}).Info("Completing multipart upload for Azure")

	blockBlobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlockBlobClient(key)

	// Create block list
	blockList := make([]string, len(parts))
	for i, part := range parts {
		// Extract block ID from ETag (remove quotes if present)
		blockID := strings.Trim(part.ETag, "\"")
		
		// If the ETag doesn't look like a base64-encoded block ID, generate it from part number
		// This handles backward compatibility or cases where ETag wasn't properly set
		if len(blockID) < 10 || !isBase64(blockID) {
			blockID = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%010d", part.PartNumber)))
			logrus.WithFields(logrus.Fields{
				"partNumber": part.PartNumber,
				"originalETag": part.ETag,
				"generatedBlockID": blockID,
			}).Warn("ETag doesn't contain valid block ID, generating from part number")
		}
		
		blockList[i] = blockID
		
		logrus.WithFields(logrus.Fields{
			"partNumber": part.PartNumber,
			"etag": part.ETag,
			"blockID": blockID,
		}).Debug("Adding block to commit list")
	}

	// Retrieve stored metadata
	var metadata map[string]string
	if storedMeta, ok := a.uploadMetadata.LoadAndDelete(uploadID); ok {
		if metaMap, ok := storedMeta.(map[string]string); ok {
			metadata = sanitizeAzureMetadata(metaMap)
		}
	}

	// Commit the block list
	opts := &blockblob.CommitBlockListOptions{
		Metadata: convertMetadataToPointers(metadata),
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: func() *string {
				ct := "application/octet-stream"
				return &ct
			}(),
		},
	}

	_, err := blockBlobClient.CommitBlockList(ctx, blockList, opts)
	if err != nil {
		return fmt.Errorf("failed to commit block list: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Successfully completed multipart upload for Azure")

	return nil
}

func (a *AzureBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	// Clean up stored metadata
	a.uploadMetadata.Delete(uploadID)
	
	// Azure doesn't have explicit abort for uncommitted blocks
	// Uncommitted blocks are automatically garbage collected
	return nil
}

func (a *AzureBackend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	blockBlobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlockBlobClient(key)
	
	// Get the block list
	blockList, err := blockBlobClient.GetBlockList(ctx, blockblob.BlockListTypeUncommitted, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block list: %w", err)
	}

	result := &ListPartsResult{
		Bucket:           bucket,
		Key:              key,
		UploadID:         uploadID,
		PartNumberMarker: partNumberMarker,
		MaxParts:         maxParts,
		Parts:            []Part{},
	}

	// Convert uncommitted blocks to parts
	for _, block := range blockList.UncommittedBlocks {
		// Decode block ID to get part number
		decoded, err := base64.StdEncoding.DecodeString(*block.Name)
		if err != nil {
			continue
		}
		
		var partNumber int
		fmt.Sscanf(string(decoded), "%d", &partNumber)
		
		if partNumber <= partNumberMarker {
			continue
		}

		result.Parts = append(result.Parts, Part{
			PartNumber: partNumber,
			ETag:       fmt.Sprintf("\"%s\"", *block.Name),
			Size:       *block.Size,
		})

		if len(result.Parts) >= maxParts {
			result.IsTruncated = true
			result.NextPartNumberMarker = partNumber
			break
		}
	}

	return result, nil
}