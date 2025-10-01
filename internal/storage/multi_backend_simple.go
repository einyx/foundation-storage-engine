package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

// MultiBackendSimple provides routing to different storage backends based on bucket name
type MultiBackendSimple struct {
	backends map[string]Backend
	routing  map[string]string // bucket -> backend name mapping
}

// NewMultiBackendSimple creates a new multi-provider backend with simple routing
func NewMultiBackendSimple(cfg *config.StorageConfig) (Backend, error) {
	mb := &MultiBackendSimple{
		backends: make(map[string]Backend),
		routing:  make(map[string]string),
	}

	// Initialize S3 backend if configured
	if cfg.S3 != nil {
		s3Backend, err := NewS3Backend(cfg.S3)
		if err != nil {
			return nil, fmt.Errorf("failed to create S3 backend: %w", err)
		}
		mb.backends["s3"] = s3Backend

		// Map S3 bucket configs to S3 backend
		for bucketAlias := range cfg.S3.BucketConfigs {
			mb.routing[bucketAlias] = "s3"
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
				mb.routing[alias] = "azure"
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

// getBackendForBucket returns the backend for a specific bucket
func (m *MultiBackendSimple) getBackendForBucket(bucket string) (Backend, error) {
	if backendName, ok := m.routing[bucket]; ok {
		if backend, ok := m.backends[backendName]; ok {
			return backend, nil
		}
	}
	
	return nil, fmt.Errorf("no backend found for bucket: %s", bucket)
}

// ListBuckets returns buckets from all configured backends
func (m *MultiBackendSimple) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	var allBuckets []BucketInfo
	
	// Get buckets from each backend
	for _, backend := range m.backends {
		buckets, err := backend.ListBuckets(ctx)
		if err != nil {
			// Continue with other backends on error
			continue
		}
		allBuckets = append(allBuckets, buckets...)
	}
	
	return allBuckets, nil
}

func (m *MultiBackendSimple) CreateBucket(ctx context.Context, bucket string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.CreateBucket(ctx, bucket)
}

func (m *MultiBackendSimple) DeleteBucket(ctx context.Context, bucket string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.DeleteBucket(ctx, bucket)
}

func (m *MultiBackendSimple) BucketExists(ctx context.Context, bucket string) (bool, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return false, err
	}
	return backend.BucketExists(ctx, bucket)
}

func (m *MultiBackendSimple) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.ListObjects(ctx, bucket, prefix, marker, maxKeys)
}

func (m *MultiBackendSimple) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, delimiter, maxKeys)
}

func (m *MultiBackendSimple) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.GetObject(ctx, bucket, key)
}

func (m *MultiBackendSimple) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.PutObject(ctx, bucket, key, reader, size, metadata)
}

func (m *MultiBackendSimple) DeleteObject(ctx context.Context, bucket, key string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.DeleteObject(ctx, bucket, key)
}

func (m *MultiBackendSimple) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.HeadObject(ctx, bucket, key)
}

func (m *MultiBackendSimple) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.GetObjectACL(ctx, bucket, key)
}

func (m *MultiBackendSimple) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.PutObjectACL(ctx, bucket, key, acl)
}

func (m *MultiBackendSimple) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return "", err
	}
	return backend.InitiateMultipartUpload(ctx, bucket, key, metadata)
}

func (m *MultiBackendSimple) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return "", err
	}
	return backend.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, size)
}

func (m *MultiBackendSimple) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
}

func (m *MultiBackendSimple) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.AbortMultipartUpload(ctx, bucket, key, uploadID)
}

func (m *MultiBackendSimple) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.ListParts(ctx, bucket, key, uploadID, maxParts, partNumberMarker)
}

// ListDeletedObjects lists soft-deleted objects from the appropriate backend
func (m *MultiBackendSimple) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return nil, err
	}
	return backend.ListDeletedObjects(ctx, bucket, prefix, marker, maxKeys)
}

// RestoreObject restores a soft-deleted object using the appropriate backend
func (m *MultiBackendSimple) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	backend, err := m.getBackendForBucket(bucket)
	if err != nil {
		return err
	}
	return backend.RestoreObject(ctx, bucket, key, versionID)
}
