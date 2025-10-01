package storage

import (
	"context"
	"io"
	"strings"
	"time"
)

// AzureWrapper wraps an Azure backend to handle bucket-to-container mapping
type AzureWrapper struct {
	backend         *AzureBackend
	containerMap    map[string]string // bucket alias -> real container name
	reverseMap      map[string]string // real container -> bucket alias
	prefixMap       map[string]string // bucket alias -> prefix
}

func NewAzureWrapper(backend *AzureBackend, containerMap map[string]string, prefixMap map[string]string) *AzureWrapper {
	reverseMap := make(map[string]string)
	for alias, real := range containerMap {
		reverseMap[real] = alias
	}
	
	return &AzureWrapper{
		backend:      backend,
		containerMap: containerMap,
		reverseMap:   reverseMap,
		prefixMap:    prefixMap,
	}
}

// translateBucketToContainer converts bucket alias to real container name
func (w *AzureWrapper) translateBucketToContainer(bucket string) string {
	if real, ok := w.containerMap[bucket]; ok {
		return real
	}
	return bucket
}

// translateContainerToBucket converts real container name to bucket alias
func (w *AzureWrapper) translateContainerToBucket(container string) string {
	if alias, ok := w.reverseMap[container]; ok {
		return alias
	}
	return container
}

// addPrefix adds the configured prefix to a key
func (w *AzureWrapper) addPrefix(bucket, key string) string {
	if prefix, ok := w.prefixMap[bucket]; ok && prefix != "" {
		return prefix + key
	}
	return key
}

// removePrefix removes the configured prefix from a key
func (w *AzureWrapper) removePrefix(bucket, key string) string {
	if prefix, ok := w.prefixMap[bucket]; ok && prefix != "" {
		return strings.TrimPrefix(key, prefix)
	}
	return key
}

// executeWithContainer executes a function with a temporary container context
func (w *AzureWrapper) executeWithContainer(container string, fn func() error) error {
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	return fn()
}


func (w *AzureWrapper) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	// For Azure, we return the configured bucket aliases
	var buckets []BucketInfo
	for alias := range w.containerMap {
		buckets = append(buckets, BucketInfo{
			Name:         alias,
			CreationDate: time.Now(), // Azure doesn't expose container creation time easily
		})
	}
	return buckets, nil
}

func (w *AzureWrapper) CreateBucket(ctx context.Context, bucket string) error {
	// Translate bucket alias to real container name
	container := w.translateBucketToContainer(bucket)
	return w.executeWithContainer(container, func() error {
		return w.backend.CreateBucket(ctx, container)
	})
}

func (w *AzureWrapper) DeleteBucket(ctx context.Context, bucket string) error {
	container := w.translateBucketToContainer(bucket)
	return w.executeWithContainer(container, func() error {
		return w.backend.DeleteBucket(ctx, container)
	})
}

func (w *AzureWrapper) BucketExists(ctx context.Context, bucket string) (bool, error) {
	container := w.translateBucketToContainer(bucket)
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	return w.backend.BucketExists(ctx, container)
}

func (w *AzureWrapper) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	container := w.translateBucketToContainer(bucket)
	fullPrefix := w.addPrefix(bucket, prefix)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	result, err := w.backend.ListObjects(ctx, container, fullPrefix, marker, maxKeys)
	if err != nil {
		return nil, err
	}
	
	// Remove prefix from results and set backend
	for i := range result.Contents {
		result.Contents[i].Key = w.removePrefix(bucket, result.Contents[i].Key)
		result.Contents[i].Backend = "azure"
	}
	
	return result, nil
}

func (w *AzureWrapper) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	container := w.translateBucketToContainer(bucket)
	fullPrefix := w.addPrefix(bucket, prefix)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	result, err := w.backend.ListObjectsWithDelimiter(ctx, container, fullPrefix, marker, delimiter, maxKeys)
	if err != nil {
		return nil, err
	}
	
	// Remove prefix from results and set backend
	for i := range result.Contents {
		result.Contents[i].Key = w.removePrefix(bucket, result.Contents[i].Key)
		result.Contents[i].Backend = "azure"
	}
	
	// Remove prefix from common prefixes
	for i := range result.CommonPrefixes {
		result.CommonPrefixes[i] = w.removePrefix(bucket, result.CommonPrefixes[i])
	}
	
	return result, nil
}

func (w *AzureWrapper) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.GetObject(ctx, container, fullKey)
}

func (w *AzureWrapper) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	return w.executeWithContainer(container, func() error {
		return w.backend.PutObject(ctx, container, fullKey, reader, size, metadata)
	})
}

func (w *AzureWrapper) DeleteObject(ctx context.Context, bucket, key string) error {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	return w.executeWithContainer(container, func() error {
		return w.backend.DeleteObject(ctx, container, fullKey)
	})
}

func (w *AzureWrapper) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	info, err := w.backend.HeadObject(ctx, container, fullKey)
	if err != nil {
		return nil, err
	}
	
	// Adjust the key in the result
	info.Key = key
	
	return info, nil
}

func (w *AzureWrapper) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.GetObjectACL(ctx, container, fullKey)
}

func (w *AzureWrapper) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.PutObjectACL(ctx, container, fullKey, acl)
}

func (w *AzureWrapper) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.InitiateMultipartUpload(ctx, container, fullKey, metadata)
}

func (w *AzureWrapper) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.UploadPart(ctx, container, fullKey, uploadID, partNumber, reader, size)
}

func (w *AzureWrapper) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.CompleteMultipartUpload(ctx, container, fullKey, uploadID, parts)
}

func (w *AzureWrapper) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.AbortMultipartUpload(ctx, container, fullKey, uploadID)
}

func (w *AzureWrapper) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.ListParts(ctx, container, fullKey, uploadID, maxParts, partNumberMarker)
}

// ListDeletedObjects delegates to the wrapped Azure backend
func (w *AzureWrapper) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	container := w.translateBucketToContainer(bucket)
	fullPrefix := w.addPrefix(bucket, prefix)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.ListDeletedObjects(ctx, container, fullPrefix, marker, maxKeys)
}

// RestoreObject delegates to the wrapped Azure backend
func (w *AzureWrapper) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	container := w.translateBucketToContainer(bucket)
	fullKey := w.addPrefix(bucket, key)
	
	oldContainer := w.backend.containerName
	w.backend.containerName = container
	defer func() { w.backend.containerName = oldContainer }()
	
	return w.backend.RestoreObject(ctx, container, fullKey, versionID)
}
