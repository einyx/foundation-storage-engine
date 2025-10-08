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

const (
	// Buffer sizes
	defaultBufferSize = 1 * 1024 * 1024 // 1MB
	smallFileThreshold = 256 * 1024     // 256KB for MD5 calculation
	
	// Azure limits and configuration
	azureBlockIDFormat = "%010d"
	maxPagesToSearch = 10
	maxConcurrentUploads = 4
	minResultsToTruncate = 10 // Minimum results to continue pagination with blob path marker
	
	// Timeouts and delays
	defaultClientTimeout = 300 * time.Second
	defaultRetryDelay = 500 * time.Millisecond
	maxRetryDelay = 5 * time.Second
	maxRetries = 1
	
	// Special markers and identifiers
	directoryMarkerSuffix = "/.dir"
	emptyFileMD5 = "d41d8cd98f00b204e9800998ecf8427e" // MD5 of empty string
	rootContainer = "$root"
	
	// Metadata keys
	metadataKeyDirectoryMarker = "s3proxyDirectoryMarker"
	metadataKeyOriginalKey = "s3proxyOriginalKey"
	metadataKeyMD5 = "s3proxyMD5"
)

// wrapAzureError adds context to Azure storage errors
func wrapAzureError(operation, bucket, key string, err error) error {
	if err == nil {
		return nil
	}
	if key != "" {
		return fmt.Errorf("%s failed for bucket=%s, key=%s: %w", operation, bucket, key, err)
	}
	return fmt.Errorf("%s failed for bucket=%s: %w", operation, bucket, err)
}

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
				MaxRetries:    maxRetries,
				TryTimeout:    defaultClientTimeout,
				RetryDelay:    defaultRetryDelay,
				MaxRetryDelay: maxRetryDelay,
			},
			Transport: &http.Client{
				Timeout: defaultClientTimeout,
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
		containerName = rootContainer
	}

	return &AzureBackend{
		client:        client,
		accountName:   cfg.AccountName,
		containerName: containerName,
		bufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, defaultBufferSize)
				return &buf
			},
		},
		uploadSem: make(chan struct{}, maxConcurrentUploads),
	}, nil
}

func (a *AzureBackend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	var buckets []BucketInfo

	pager := a.client.NewListContainersPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapAzureError("list containers", "", "", err)
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
		return wrapAzureError("create container", bucket, "", err)
	}
	return nil
}

func (a *AzureBackend) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := a.client.DeleteContainer(ctx, bucket, nil)
	if err != nil {
		return wrapAzureError("delete container", bucket, "", err)
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
	
	// Fix for Azure marker issue: Some S3 clients (like Iceberg/Trino) use the last object key
	// as the continuation token instead of the NextContinuationToken. This doesn't work with Azure.
	// If the marker looks like a blob path, we need to handle it specially.
	if marker != "" {
		if strings.Contains(marker, "/") {
			// This is a blob path being used as a marker (common S3 client behavior)
			// We need to find all blobs after this key
			logrus.WithFields(logrus.Fields{
				"marker": marker,
				"bucket": bucket,
				"prefix": prefix,
			}).Debug("Detected blob path used as marker, will filter results")
			
			// Use a smarter prefix to reduce the search space
			// Extract the directory part of the marker to use as a prefix hint
			if lastSlash := strings.LastIndex(marker, "/"); lastSlash > 0 && prefix == "" {
				// Use the directory of the marker as a prefix to narrow the search
				markerDir := marker[:lastSlash+1]
				if strings.HasPrefix(markerDir, prefix) {
					opts.Prefix = &markerDir
				}
			}
			
			// Don't set the Azure marker - we'll filter results manually
			// by skipping all blobs until we pass the marker key
		} else {
			// This looks like a valid Azure marker
			opts.Marker = &marker
		}
	}

	// Track if we're using a blob path as marker and need to skip entries
	skipUntilAfterMarker := marker != "" && strings.Contains(marker, "/")
	markerPath := marker
	// Track if we found anything past the marker
	foundItemsPastMarker := false
	// Limit pages when searching for marker to prevent excessive API calls
	pagesSearched := 0
	
	if delimiter != "" {
		// Use hierarchical listing
		pager := containerClient.NewListBlobsHierarchyPager(delimiter, opts)
		
		// Continue paging if we need more items OR if we're still searching for items past the marker (with page limit)
		for pager.More() && (len(result.Contents) < maxKeys || (skipUntilAfterMarker && !foundItemsPastMarker && pagesSearched < maxPagesToSearch)) {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, wrapAzureError("list blobs", bucket, prefix, err)
			}
			pagesSearched++

			// Process blobs
			for _, blob := range page.Segment.BlobItems {
				if len(result.Contents) >= maxKeys {
					result.IsTruncated = true
					break
				}

				key := *blob.Name
				
				// Skip blobs until we pass the marker if using blob path as marker
				if skipUntilAfterMarker {
					if key <= markerPath {
						continue
					}
					// We've passed the marker, stop skipping
					skipUntilAfterMarker = false
					foundItemsPastMarker = true
				}
				// Convert .dir blobs back to directory names
				if strings.HasSuffix(key, directoryMarkerSuffix) && blob.Metadata != nil {
					if isDir, exists := blob.Metadata[metadataKeyDirectoryMarker]; exists && isDir != nil && *isDir == "true" {
						if origKey, exists := blob.Metadata[metadataKeyOriginalKey]; exists && origKey != nil {
							key = *origKey
						} else {
							key = strings.TrimSuffix(key, directoryMarkerSuffix) + "/"
						}
					}
				}

				etag := string(*blob.Properties.ETag)
				if blob.Metadata != nil {
					if md5Hash, exists := blob.Metadata[metadataKeyMD5]; exists && md5Hash != nil {
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

			// Handle pagination carefully when using blob paths as markers
			if len(result.Contents) >= maxKeys {
				// We hit the max keys limit, need to set next marker
				result.IsTruncated = true
				if len(result.Contents) > 0 {
					// Use the last item as the next marker for blob path scenarios
					result.NextMarker = result.Contents[len(result.Contents)-1].Key
				}
			} else if page.NextMarker != nil {
				// Special handling when using a blob path as marker
				if marker != "" && strings.Contains(marker, "/") {
					// For blob path markers, check if we found any results after extensive searching
					if len(result.Contents) == 0 || (pagesSearched >= maxPagesToSearch && len(result.Contents) < minResultsToTruncate) {
						// No results or very few results after extensive search - end pagination
						result.IsTruncated = false
						result.NextMarker = ""
						logrus.WithFields(logrus.Fields{
							"bucket": bucket,
							"prefix": prefix,
							"marker": marker,
							"results": len(result.Contents),
							"pagesSearched": pagesSearched,
						}).Info("Ending pagination: blob path marker with few results")
					} else if len(result.Contents) > 0 {
						// Check if we made progress
						lastKey := result.Contents[len(result.Contents)-1].Key
						if lastKey <= marker {
							// No progress made - we're stuck
							result.IsTruncated = false
							result.NextMarker = ""
							logrus.WithFields(logrus.Fields{
								"bucket": bucket,
								"prefix": prefix,
								"marker": marker,
								"lastKey": lastKey,
							}).Warn("Preventing infinite loop: no progress from marker")
						} else {
							// Use the last key as the next marker
							result.NextMarker = lastKey
							result.IsTruncated = true
						}
					} else {
						// No results found
					result.IsTruncated = false
					result.NextMarker = ""
					}
				} else if len(result.Contents) > 0 {
					// Normal case: Azure has more pages and we have results
					result.NextMarker = *page.NextMarker
					result.IsTruncated = true
				} else {
					// No results found
					result.IsTruncated = false
					result.NextMarker = ""
				}
			}
		}
	} else {
		// Flat listing
		flatOpts := &container.ListBlobsFlatOptions{
			Prefix: &prefix,
			MaxResults: func() *int32 { 
				mk := int32(maxKeys)
				return &mk 
			}(),
		}
		
		// Only set marker if it's a valid Azure marker (not a blob path)
		if marker != "" && !strings.Contains(marker, "/") {
			flatOpts.Marker = &marker
		}
		
		pager := containerClient.NewListBlobsFlatPager(flatOpts)
		
		// Continue paging if we need more items OR if we're still searching for items past the marker (with page limit)
		for pager.More() && (len(result.Contents) < maxKeys || (skipUntilAfterMarker && !foundItemsPastMarker && pagesSearched < maxPagesToSearch)) {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, wrapAzureError("list blobs", bucket, prefix, err)
			}
			pagesSearched++

			for _, blob := range page.Segment.BlobItems {
				if len(result.Contents) >= maxKeys {
					result.IsTruncated = true
					break
				}

				key := *blob.Name
				
				// Skip blobs until we pass the marker if using blob path as marker
				if skipUntilAfterMarker {
					if key <= markerPath {
						continue
					}
					// We've passed the marker, stop skipping
					skipUntilAfterMarker = false
					foundItemsPastMarker = true
				}
				// Convert .dir blobs back to directory names
				if strings.HasSuffix(key, directoryMarkerSuffix) && blob.Metadata != nil {
					if isDir, exists := blob.Metadata[metadataKeyDirectoryMarker]; exists && isDir != nil && *isDir == "true" {
						if origKey, exists := blob.Metadata[metadataKeyOriginalKey]; exists && origKey != nil {
							key = *origKey
						} else {
							key = strings.TrimSuffix(key, directoryMarkerSuffix) + "/"
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

			// Handle pagination carefully when using blob paths as markers
			if len(result.Contents) >= maxKeys {
				// We hit the max keys limit, need to set next marker
				result.IsTruncated = true
				if len(result.Contents) > 0 {
					// Use the last item as the next marker for blob path scenarios
					result.NextMarker = result.Contents[len(result.Contents)-1].Key
				}
			} else if page.NextMarker != nil {
				// Special handling when using a blob path as marker
				if marker != "" && strings.Contains(marker, "/") {
					// For blob path markers, check if we found any results after extensive searching
					if len(result.Contents) == 0 || (pagesSearched >= maxPagesToSearch && len(result.Contents) < minResultsToTruncate) {
						// No results or very few results after extensive search - end pagination
						result.IsTruncated = false
						result.NextMarker = ""
						logrus.WithFields(logrus.Fields{
							"bucket": bucket,
							"prefix": prefix,
							"marker": marker,
							"results": len(result.Contents),
							"pagesSearched": pagesSearched,
						}).Info("Ending pagination: blob path marker with few results")
					} else if len(result.Contents) > 0 {
						// Check if we made progress
						lastKey := result.Contents[len(result.Contents)-1].Key
						if lastKey <= marker {
							// No progress made - we're stuck
							result.IsTruncated = false
							result.NextMarker = ""
							logrus.WithFields(logrus.Fields{
								"bucket": bucket,
								"prefix": prefix,
								"marker": marker,
								"lastKey": lastKey,
							}).Warn("Preventing infinite loop: no progress from marker")
						} else {
							// Use the last key as the next marker
							result.NextMarker = lastKey
							result.IsTruncated = true
						}
					} else {
						// No results found
					result.IsTruncated = false
					result.NextMarker = ""
					}
				} else if len(result.Contents) > 0 {
					// Normal case: Azure has more pages and we have results
					result.NextMarker = *page.NextMarker
					result.IsTruncated = true
				} else {
					// No results found
					result.IsTruncated = false
					result.NextMarker = ""
				}
			}
		}
	}

	return result, nil
}

// ListDeletedObjects lists soft-deleted blobs in Azure Blob Storage
func (a *AzureBackend) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"prefix": prefix,
		"marker": marker,
		"maxKeys": maxKeys,
	}).Debug("ListDeletedObjects called")
	
	result := &ListObjectsResult{
		CommonPrefixes: []string{},
		Contents:       []ObjectInfo{},
	}

	containerClient := a.client.ServiceClient().NewContainerClient(bucket)
	
	// Create options with Include for deleted blobs
	// Include all possible states to debug
	includeStates := container.ListBlobsInclude{
		Deleted:   true,
		Metadata:  true,
		Snapshots: false, // Don't include snapshots as they might confuse the listing
		Tags:      true,
		Versions:  true, // Re-enable versions to see all blob states
	}
	
	opts := &container.ListBlobsFlatOptions{
		Prefix: &prefix,
		MaxResults: func() *int32 { 
			mk := int32(maxKeys)
			return &mk 
		}(),
		Include: includeStates,
	}
	
	if marker != "" {
		opts.Marker = &marker
	}

	// Use flat listing for deleted blobs
	pager := containerClient.NewListBlobsFlatPager(opts)
	
	totalBlobsProcessed := 0
	deletedBlobsFound := 0
	
	for pager.More() && len(result.Contents) < maxKeys {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapAzureError("list deleted blobs", bucket, prefix, err)
		}

		logrus.WithFields(logrus.Fields{
			"pageSize": len(page.Segment.BlobItems),
			"bucket": bucket,
			"totalProcessed": totalBlobsProcessed,
			"deletedFound": deletedBlobsFound,
		}).Info("Processing page of blobs for soft delete listing")
		
		// Process blobs - only include deleted ones
		for _, blob := range page.Segment.BlobItems {
			if len(result.Contents) >= maxKeys {
				result.IsTruncated = true
				if page.NextMarker != nil && *page.NextMarker != "" {
					result.NextMarker = *page.NextMarker
				}
				break
			}

			// Log first few blobs to debug
			if totalBlobsProcessed < 5 && blob.Name != nil {
				fields := logrus.Fields{
					"name": *blob.Name,
					"hasDeleted": blob.Deleted != nil,
					"hasIsCurrentVersion": blob.IsCurrentVersion != nil,
					"hasVersionID": blob.VersionID != nil,
				}
				
				if blob.Deleted != nil {
					fields["deleted"] = *blob.Deleted
				}
				if blob.IsCurrentVersion != nil {
					fields["isCurrentVersion"] = *blob.IsCurrentVersion
				}
				if blob.VersionID != nil {
					fields["versionID"] = *blob.VersionID
				}
				
				logrus.WithFields(fields).Info("Sample blob properties for debugging")
			}
			
			totalBlobsProcessed++
			
			// Check if blob is deleted
			// Azure SDK issue: blob.Deleted is not populated when versioning is enabled
			// We need to check multiple conditions
			isDeleted := false
			
			// Method 1: Check the Deleted flag (might not work with versioning)
			if blob.Deleted != nil && *blob.Deleted {
				isDeleted = true
				logrus.WithField("method", "DeletedFlag").Debug("Found deleted blob via Deleted flag")
			}
			
			// Method 2: Check if DeletedTime is set
			if !isDeleted && blob.Properties != nil && blob.Properties.DeletedTime != nil {
				isDeleted = true
				logrus.WithField("method", "DeletedTime").Debug("Found deleted blob via DeletedTime")
			}
			
			// Method 3: When versioning is enabled, check if this is not the current version
			// Previous versions are soft-deleted blobs when versioning + soft delete are enabled
			if !isDeleted && blob.VersionID != nil {
				// If IsCurrentVersion is explicitly false, it's a previous version
				if blob.IsCurrentVersion != nil && !*blob.IsCurrentVersion {
					isDeleted = true
					logrus.WithFields(logrus.Fields{
						"name": *blob.Name,
						"versionID": *blob.VersionID,
						"method": "PreviousVersion-ExplicitFalse",
					}).Info("Found deleted blob via previous version detection")
				} else if blob.IsCurrentVersion == nil {
					// When IsCurrentVersion is not set (nil), it's also a previous version!
					// Azure doesn't set this property for non-current versions
					isDeleted = true
					logrus.WithFields(logrus.Fields{
						"name": *blob.Name,
						"versionID": *blob.VersionID,
						"method": "PreviousVersion-NilFlag",
					}).Info("Found deleted blob via previous version detection (nil IsCurrentVersion)")
				}
			}
			
			// Method 4: Check for any deletion properties for debugging
			if blob.Properties != nil {
				deletionInfo := logrus.Fields{
					"name": *blob.Name,
				}
				
				hasAnyIndicator := false
				if blob.Properties.DeletedTime != nil {
					deletionInfo["deletedTime"] = *blob.Properties.DeletedTime
					hasAnyIndicator = true
				}
				if blob.Properties.RemainingRetentionDays != nil {
					deletionInfo["remainingRetentionDays"] = *blob.Properties.RemainingRetentionDays
					hasAnyIndicator = true
				}
				if blob.Deleted != nil {
					deletionInfo["deletedFlag"] = *blob.Deleted
				}
				if blob.IsCurrentVersion != nil {
					deletionInfo["isCurrentVersion"] = *blob.IsCurrentVersion
				}
				if blob.VersionID != nil {
					deletionInfo["versionID"] = *blob.VersionID
				}
				
				// Log for debugging
				if hasAnyIndicator || (blob.IsCurrentVersion != nil && !*blob.IsCurrentVersion) {
					logrus.WithFields(deletionInfo).Debug("Blob version info")
				}
			}
			
			// Only include deleted blobs
			if isDeleted {
				deletedBlobsFound++
				key := *blob.Name
				etag := ""
				if blob.Properties.ETag != nil {
					etag = string(*blob.Properties.ETag)
					etag = strings.Trim(etag, `"`)
				}

				size := int64(0)
				if blob.Properties.ContentLength != nil {
					size = *blob.Properties.ContentLength
				}

				lastModified := time.Time{}
				if blob.Properties.LastModified != nil {
					lastModified = *blob.Properties.LastModified
				}

				// Get deleted time - use LastModified as DeletedOn might not be available
				deletedTime := time.Time{}
				if blob.Properties.LastModified != nil {
					deletedTime = *blob.Properties.LastModified
				}

				// Get version ID if available
				versionID := ""
				if blob.VersionID != nil {
					versionID = *blob.VersionID
				}

				result.Contents = append(result.Contents, ObjectInfo{
					Key:          key,
					Size:         size,
					ETag:         etag,
					LastModified: lastModified,
					StorageClass: "STANDARD",
					Metadata: map[string]string{
						"DeletedTime": deletedTime.Format(time.RFC3339),
						"VersionID":   versionID,
						"IsDeleted":   "true",
					},
				})
			}
		}

		// Check if we have a next marker
		if page.NextMarker != nil && *page.NextMarker != "" {
			result.NextMarker = *page.NextMarker
			if len(result.Contents) >= maxKeys {
				result.IsTruncated = true
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"deletedCount": len(result.Contents),
		"isTruncated": result.IsTruncated,
	}).Info("ListDeletedObjects completed")
	
	return result, nil
}

func (a *AzureBackend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + directoryMarkerSuffix
	}

	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlobClient(normalizedKey)
	
	// Get properties first
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, wrapAzureError("get blob properties", bucket, normalizedKey, err)
	}

	// Download the blob
	downloadResponse, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		return nil, wrapAzureError("download blob", bucket, normalizedKey, err)
	}

	// Get metadata
	metadata := make(map[string]string)
	if props.Metadata != nil {
		metadata = desanitizeAzureMetadata(props.Metadata)
	}

	// Use stored MD5 hash as ETag for S3 compatibility
	etag := string(*props.ETag)
	if md5Hash, exists := metadata[metadataKeyMD5]; exists {
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
		normalizedKey = strings.TrimSuffix(key, "/") + directoryMarkerSuffix
		metadata[metadataKeyDirectoryMarker] = "true"
		metadata[metadataKeyOriginalKey] = key
		metadata[metadataKeyMD5] = emptyFileMD5
	}

	// For small files, calculate MD5
	if size < smallFileThreshold {
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("failed to read data: %w", err)
		}
		
		// Calculate MD5
		hash := md5.Sum(data)
		md5Hash := hex.EncodeToString(hash[:])
		metadata[metadataKeyMD5] = md5Hash
		
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
		return wrapAzureError("upload blob", bucket, normalizedKey, err)
	}

	return nil
}

func (a *AzureBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + directoryMarkerSuffix
	}

	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    normalizedKey,
	}).Info("Azure DeleteObject called")

	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlobClient(normalizedKey)
	
	// First try to delete with default options
	_, err := blobClient.Delete(ctx, nil)
	if err != nil {
		// Check if it's a 404 error - S3 returns success for non-existent objects
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) {
			if respErr.StatusCode == http.StatusNotFound {
				return nil
			}
			
			// If we get a 409 Conflict, it might be because of snapshots
			// Try deleting with snapshots included
			if respErr.StatusCode == http.StatusConflict {
				logrus.WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    normalizedKey,
					"error":  err.Error(),
				}).Warn("Delete failed with conflict, trying to delete including snapshots")
				
				// Try again with delete snapshots option
				deleteOptions := &blob.DeleteOptions{
					DeleteSnapshots: func() *blob.DeleteSnapshotsOptionType {
						val := blob.DeleteSnapshotsOptionTypeInclude
						return &val
					}(),
				}
				_, err = blobClient.Delete(ctx, deleteOptions)
				if err != nil {
					return fmt.Errorf("failed to delete blob with snapshots: %w", err)
				}
				return nil
			}
		}
		return fmt.Errorf("failed to delete blob: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    normalizedKey,
	}).Info("Azure DeleteObject succeeded - blob should be soft-deleted")

	return nil
}

// RestoreObject restores a soft-deleted blob
func (a *AzureBackend) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlockBlobClient(key)
	
	// Create undelete options
	opts := &blob.UndeleteOptions{}
	
	// Undelete the blob
	_, err := blobClient.Undelete(ctx, opts)
	if err != nil {
		return wrapAzureError("restore blob", bucket, key, err)
	}
	
	logrus.WithFields(logrus.Fields{
		"bucket":    bucket,
		"key":       key,
		"versionID": versionID,
	}).Info("Restored soft-deleted blob")
	
	return nil
}

func (a *AzureBackend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	// Handle directory-like objects
	normalizedKey := key
	if strings.HasSuffix(key, "/") && key != "/" {
		normalizedKey = strings.TrimSuffix(key, "/") + directoryMarkerSuffix
	}

	blobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlobClient(normalizedKey)
	
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, wrapAzureError("get blob properties", bucket, normalizedKey, err)
	}

	// Get metadata
	metadata := make(map[string]string)
	if props.Metadata != nil {
		metadata = desanitizeAzureMetadata(props.Metadata)
	}

	// Use stored MD5 hash as ETag for S3 compatibility
	etag := string(*props.ETag)
	if md5Hash, exists := metadata[metadataKeyMD5]; exists {
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
	// Acquire semaphore
	select {
	case a.uploadSem <- struct{}{}:
		defer func() { <-a.uploadSem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	logrus.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"size":       size,
	}).Info("Azure UploadPart called")

	// Azure requires block IDs to be base64-encoded and of equal length
	blockID := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(azureBlockIDFormat, partNumber)))
	
	logrus.WithFields(logrus.Fields{
		"partNumber": partNumber,
		"blockID": blockID,
		"blockIDLen": len(blockID),
	}).Debug("Generated block ID for Azure")

	// Get block blob client
	blockBlobClient := a.client.ServiceClient().NewContainerClient(bucket).NewBlockBlobClient(key)

	// Buffer the data for Azure SDK
	data, err := io.ReadAll(io.LimitReader(reader, size))
	if err != nil {
		return "", fmt.Errorf("failed to read part data: %w", err)
	}

	if int64(len(data)) != size {
		logrus.WithFields(logrus.Fields{
			"expected": size,
			"actual":   len(data),
		}).Warn("Part size mismatch")
	}

	// Stage the block
	_, err = blockBlobClient.StageBlock(ctx, blockID, streaming.NopCloser(bytes.NewReader(data)), nil)
	if err != nil {
		return "", fmt.Errorf("failed to stage block: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"blockID":    blockID,
		"partNumber": partNumber,
		"size":       size,
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
			blockID = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(azureBlockIDFormat, part.PartNumber)))
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