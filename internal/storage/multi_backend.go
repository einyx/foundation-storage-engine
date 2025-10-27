package storage

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

// MultiBackend provides routing to different storage backends based on bucket configuration
type MultiBackend struct {
	backends        map[string]Backend
	routing         map[string][]string // bucket -> list of backends that have this bucket
	azureContainers map[string]string   // bucket alias -> real container name mapping for Azure
	s3Buckets       map[string]string   // bucket alias -> real bucket name mapping for S3
}

// NewMultiBackend creates a new multi-provider backend
func NewMultiBackend(cfg *config.StorageConfig) (Backend, error) {
	mb := &MultiBackend{
		backends:        make(map[string]Backend),
		routing:         make(map[string][]string),
		azureContainers: make(map[string]string),
		s3Buckets:       make(map[string]string),
	}

	// Initialize S3 backend if configured
	if cfg.S3 != nil {
		// Log S3 configuration for debugging
		fmt.Printf("Creating S3 backend with profile: %s, region: %s\n", cfg.S3.Profile, cfg.S3.Region)
		
		s3Backend, err := NewS3Backend(cfg.S3)
		if err != nil {
			return nil, fmt.Errorf("failed to create S3 backend: %w", err)
		}
		mb.backends["s3"] = s3Backend

		// Map S3 bucket configs to S3 backend
		for bucketAlias := range cfg.S3.BucketConfigs {
			mb.routing[bucketAlias] = append(mb.routing[bucketAlias], "s3")
		}
	}

	// Initialize Azure backend if configured
	if cfg.Azure != nil {
		azureBackend, err := NewAzureBackend(cfg.Azure)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure backend: %w", err)
		}
		
		// Create container and prefix maps
		containerMap := make(map[string]string)
		prefixMap := make(map[string]string)
		
		if cfg.Azure.ContainerConfigs != nil {
			for alias, containerCfg := range cfg.Azure.ContainerConfigs {
				containerMap[alias] = containerCfg.ContainerName
				prefixMap[alias] = containerCfg.Prefix
				mb.routing[alias] = append(mb.routing[alias], "azure")
				mb.azureContainers[alias] = containerCfg.ContainerName
			}
		}
		
		// Wrap the Azure backend to handle bucket-to-container mapping
		azureWrapper := NewAzureWrapper(azureBackend, containerMap, prefixMap)
		mb.backends["azure"] = azureWrapper
	}

	// Initialize filesystem backend if configured
	if cfg.FileSystem != nil {
		fsBackend, err := NewFileSystemBackend(cfg.FileSystem)
		if err != nil {
			return nil, fmt.Errorf("failed to create filesystem backend: %w", err)
		}
		mb.backends["filesystem"] = fsBackend
	}

	if len(mb.backends) == 0 {
		return nil, fmt.Errorf("no storage backends configured for multi-provider")
	}

	return mb, nil
}

// getBackendsForBucket returns all backends that have this bucket
func (m *MultiBackend) getBackendsForBucket(bucket string) []Backend {
	var backends []Backend
	
	if backendNames, ok := m.routing[bucket]; ok {
		for _, backendName := range backendNames {
			if backend, ok := m.backends[backendName]; ok {
				backends = append(backends, backend)
			}
		}
	}
	
	// If no specific routing, return first available backend
	if len(backends) == 0 {
		for _, backend := range m.backends {
			backends = append(backends, backend)
			break
		}
	}
	
	return backends
}

// getBackendForBucket returns the primary backend for write operations
func (m *MultiBackend) getBackendForBucket(bucket string) (Backend, error) {
	backends := m.getBackendsForBucket(bucket)
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backend available for bucket: %s", bucket)
	}
	// For writes, prefer S3 over Azure
	for _, backend := range backends {
		if _, ok := m.backends["s3"]; ok && backend == m.backends["s3"] {
			return backend, nil
		}
	}
	return backends[0], nil
}

// ListBuckets returns unique buckets from all configured backends
func (m *MultiBackend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	bucketMap := make(map[string]BucketInfo)
	
	// Collect buckets from all backends
	for _, backend := range m.backends {
		buckets, err := backend.ListBuckets(ctx)
		if err != nil {
			// Continue with other backends on error
			continue
		}
		
		for _, bucket := range buckets {
			// If bucket doesn't exist in map, add it
			if _, exists := bucketMap[bucket.Name]; !exists {
				bucketMap[bucket.Name] = bucket
			}
		}
	}
	
	// Convert map to slice
	var allBuckets []BucketInfo
	for _, bucket := range bucketMap {
		allBuckets = append(allBuckets, bucket)
	}
	
	// Sort by name for consistent output
	sort.Slice(allBuckets, func(i, j int) bool {
		return allBuckets[i].Name < allBuckets[j].Name
	})
	
	return allBuckets, nil
}

func (m *MultiBackend) CreateBucket(ctx context.Context, bucket string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.CreateBucket(ctx, bucket)
}

func (m *MultiBackend) DeleteBucket(ctx context.Context, bucket string) error {
	// Delete from all backends that have this bucket
	backends := m.getBackendsForBucket(bucket)
	var lastErr error
	
	for _, backend := range backends {
		if err := backend.DeleteBucket(ctx, bucket); err != nil {
			lastErr = err
		}
	}
	
	return lastErr
}

func (m *MultiBackend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	backends := m.getBackendsForBucket(bucket)
	
	for _, backend := range backends {
		exists, err := backend.BucketExists(ctx, bucket)
		if err == nil && exists {
			return true, nil
		}
	}
	
	return false, nil
}

// ListObjects merges results from all backends that have this bucket
func (m *MultiBackend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	backends := m.getBackendsForBucket(bucket)
	
	if len(backends) == 1 {
		// Single backend, just pass through
		return backends[0].ListObjects(ctx, bucket, prefix, marker, maxKeys)
	}
	
	// Merge results from multiple backends
	allObjects := make(map[string]ObjectInfo)
	commonPrefixes := make(map[string]bool)
	var backendNextMarker string
	var backendIsTruncated bool
	
	for _, backend := range backends {
		result, err := backend.ListObjects(ctx, bucket, prefix, marker, maxKeys)
		if err != nil {
			continue // Skip failed backends
		}
		
		// Preserve backend-specific continuation tokens
		if result.IsTruncated && result.NextMarker != "" {
			backendNextMarker = result.NextMarker
			backendIsTruncated = true
		}
		
		// Add backend source to each object
		backendName := m.getBackendName(backend)
		for _, obj := range result.Contents {
			obj.Backend = backendName
			// Use key as unique identifier, prefer S3 over Azure if duplicate
			if _, exists := allObjects[obj.Key]; !exists || backendName == "s3" {
				allObjects[obj.Key] = obj
			}
		}
		
		// Merge common prefixes
		for _, prefix := range result.CommonPrefixes {
			commonPrefixes[prefix] = true
		}
	}
	
	// Convert map to sorted slice
	var objects []ObjectInfo
	for _, obj := range allObjects {
		objects = append(objects, obj)
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})
	
	// Apply marker and maxKeys
	var filteredObjects []ObjectInfo
	foundMarker := marker == ""
	for _, obj := range objects {
		if !foundMarker {
			if obj.Key == marker {
				foundMarker = true
			}
			continue
		}
		filteredObjects = append(filteredObjects, obj)
		if len(filteredObjects) >= maxKeys {
			break
		}
	}
	
	// Convert prefixes map to slice
	var prefixList []string
	for prefix := range commonPrefixes {
		prefixList = append(prefixList, prefix)
	}
	sort.Strings(prefixList)
	
	result := &ListObjectsResult{
		IsTruncated:    len(filteredObjects) == maxKeys && len(filteredObjects) < len(objects),
		Contents:       filteredObjects,
		CommonPrefixes: prefixList,
	}
	
	// Use backend-specific NextMarker if available, otherwise fall back to key-based marker
	if result.IsTruncated || backendIsTruncated {
		if backendNextMarker != "" {
			result.NextMarker = backendNextMarker
			result.IsTruncated = true
		} else if len(filteredObjects) > 0 {
			result.NextMarker = filteredObjects[len(filteredObjects)-1].Key
		}
	}
	
	return result, nil
}

func (m *MultiBackend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	backends := m.getBackendsForBucket(bucket)
	
	if len(backends) == 1 {
		// Single backend, just pass through
		return backends[0].ListObjectsWithDelimiter(ctx, bucket, prefix, marker, delimiter, maxKeys)
	}
	
	// Merge results from multiple backends
	allObjects := make(map[string]ObjectInfo)
	commonPrefixes := make(map[string]bool)
	var backendNextMarker string
	var backendIsTruncated bool
	
	for _, backend := range backends {
		result, err := backend.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, delimiter, maxKeys)
		if err != nil {
			continue // Skip failed backends
		}
		
		// Preserve backend-specific continuation tokens
		if result.IsTruncated && result.NextMarker != "" {
			backendNextMarker = result.NextMarker
			backendIsTruncated = true
		}
		
		// Add backend source to each object
		backendName := m.getBackendName(backend)
		for _, obj := range result.Contents {
			obj.Backend = backendName
			// Use key as unique identifier, prefer S3 over Azure if duplicate
			if _, exists := allObjects[obj.Key]; !exists || backendName == "s3" {
				allObjects[obj.Key] = obj
			}
		}
		
		// Merge common prefixes
		for _, prefix := range result.CommonPrefixes {
			commonPrefixes[prefix] = true
		}
	}
	
	// Convert map to sorted slice
	var objects []ObjectInfo
	for _, obj := range allObjects {
		objects = append(objects, obj)
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})
	
	// Apply marker and maxKeys
	var filteredObjects []ObjectInfo
	foundMarker := marker == ""
	for _, obj := range objects {
		if !foundMarker {
			if obj.Key == marker {
				foundMarker = true
			}
			continue
		}
		filteredObjects = append(filteredObjects, obj)
		if len(filteredObjects) >= maxKeys {
			break
		}
	}
	
	// Convert prefixes map to slice
	var prefixList []string
	for prefix := range commonPrefixes {
		prefixList = append(prefixList, prefix)
	}
	sort.Strings(prefixList)
	
	result := &ListObjectsResult{
		IsTruncated:    len(filteredObjects) == maxKeys && len(filteredObjects) < len(objects),
		Contents:       filteredObjects,
		CommonPrefixes: prefixList,
	}
	
	// Use backend-specific NextMarker if available, otherwise fall back to key-based marker
	if result.IsTruncated || backendIsTruncated {
		if backendNextMarker != "" {
			result.NextMarker = backendNextMarker
			result.IsTruncated = true
		} else if len(filteredObjects) > 0 {
			result.NextMarker = filteredObjects[len(filteredObjects)-1].Key
		}
	}
	
	return result, nil
}

// getBackendName returns the name of a backend
func (m *MultiBackend) getBackendName(backend Backend) string {
	for name, b := range m.backends {
		if b == backend {
			return name
		}
	}
	return "unknown"
}

func (m *MultiBackend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	// Try each backend until we find the object
	backends := m.getBackendsForBucket(bucket)
	
	for _, backend := range backends {
		obj, err := backend.GetObject(ctx, bucket, key)
		if err == nil {
			// Add backend info to metadata
			if obj.Metadata == nil {
				obj.Metadata = make(map[string]string)
			}
			obj.Metadata["x-backend-source"] = m.getBackendName(backend)
			return obj, nil
		}
		// Continue to next backend if object not found
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "NoSuchKey") {
			continue
		}
		// Return error for other types of errors
		return nil, err
	}
	
	return nil, fmt.Errorf("object not found in any backend")
}

func (m *MultiBackend) GetObjectRange(ctx context.Context, bucket, key string, start, end int64) (*Object, error) {
	// Try each backend until we find the object
	backends := m.getBackendsForBucket(bucket)
	
	for _, backend := range backends {
		obj, err := backend.GetObjectRange(ctx, bucket, key, start, end)
		if err == nil {
			// Add backend info to metadata
			if obj.Metadata == nil {
				obj.Metadata = make(map[string]string)
			}
			obj.Metadata["x-backend-source"] = m.getBackendName(backend)
			return obj, nil
		}
		// Continue to next backend if object not found
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "NoSuchKey") {
			continue
		}
		// Return error for other types of errors
		return nil, err
	}
	
	return nil, fmt.Errorf("object not found in any backend")
}

func (m *MultiBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.PutObject(ctx, bucket, key, reader, size, metadata)
}

func (m *MultiBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	// Delete from all backends that have this object
	backends := m.getBackendsForBucket(bucket)
	var lastErr error
	deleted := false
	
	for _, backend := range backends {
		if err := backend.DeleteObject(ctx, bucket, key); err != nil {
			if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "NoSuchKey") {
				lastErr = err
			}
		} else {
			deleted = true
		}
	}
	
	if deleted {
		return nil
	}
	
	return lastErr
}

func (m *MultiBackend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	// Try each backend until we find the object
	backends := m.getBackendsForBucket(bucket)
	
	for _, backend := range backends {
		info, err := backend.HeadObject(ctx, bucket, key)
		if err == nil {
			// Add backend info
			info.Backend = m.getBackendName(backend)
			return info, nil
		}
		// Continue to next backend if object not found
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "NoSuchKey") {
			continue
		}
		// Return error for other types of errors
		return nil, err
	}
	
	return nil, fmt.Errorf("object not found in any backend")
}

func (m *MultiBackend) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	// Try to get ACL from the backend that has the object
	backends := m.getBackendsForBucket(bucket)
	
	for _, backend := range backends {
		// First check if object exists in this backend
		if _, err := backend.HeadObject(ctx, bucket, key); err == nil {
			return backend.GetObjectACL(ctx, bucket, key)
		}
	}
	
	return nil, fmt.Errorf("object not found in any backend")
}

func (m *MultiBackend) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	// Apply ACL to the backend that has the object
	backends := m.getBackendsForBucket(bucket)
	
	for _, backend := range backends {
		// First check if object exists in this backend
		if _, err := backend.HeadObject(ctx, bucket, key); err == nil {
			return backend.PutObjectACL(ctx, bucket, key, acl)
		}
	}
	
	return fmt.Errorf("object not found in any backend")
}

func (m *MultiBackend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return "", err
	}
	return backend.InitiateMultipartUpload(ctx, bucket, key, metadata)
}

func (m *MultiBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return "", err
	}
	return backend.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, size)
}

func (m *MultiBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
}

func (m *MultiBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.AbortMultipartUpload(ctx, bucket, key, uploadID)
}

func (m *MultiBackend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.ListParts(ctx, bucket, key, uploadID, maxParts, partNumberMarker)
}

// ListDeletedObjects lists soft-deleted objects from the appropriate backend
func (m *MultiBackend) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.ListDeletedObjects(ctx, bucket, prefix, marker, maxKeys)
}

// RestoreObject restores a soft-deleted object using the appropriate backend
func (m *MultiBackend) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.RestoreObject(ctx, bucket, key, versionID)
}
