// Package cache provides high-performance caching for S3 objects
package cache

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/einyx/s3proxy-go/internal/storage"
)

// ObjectCache provides high-performance caching for S3 objects
type ObjectCache struct {
	// Hot cache for frequently accessed small objects (in-memory)
	hotCache *lru.TwoQueueCache[string, *cachedObject]

	// Metadata cache for object info
	metaCache *lru.TwoQueueCache[string, *storage.ObjectInfo]

	// Configuration
	maxMemory     int64
	maxObjectSize int64
	ttl           time.Duration

	// Stats
	hits   uint64
	misses uint64
	mu     sync.RWMutex
}

type cachedObject struct {
	data      []byte
	info      *storage.ObjectInfo
	expiresAt time.Time
}

// NewObjectCache creates a new object cache
func NewObjectCache(maxMemory, maxObjectSize int64, ttl time.Duration) (*ObjectCache, error) {
	// Calculate cache sizes
	hotCacheSize := int(maxMemory / maxObjectSize / 2) // Half memory for hot cache
	if hotCacheSize < 100 {
		hotCacheSize = 100
	}

	metaCacheSize := hotCacheSize * 10 // 10x more metadata entries

	hotCache, err := lru.New2Q[string, *cachedObject](hotCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create hot cache: %w", err)
	}

	metaCache, err := lru.New2Q[string, *storage.ObjectInfo](metaCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata cache: %w", err)
	}

	return &ObjectCache{
		hotCache:      hotCache,
		metaCache:     metaCache,
		maxMemory:     maxMemory,
		maxObjectSize: maxObjectSize,
		ttl:           ttl,
	}, nil
}

// GetObject retrieves an object from cache
func (c *ObjectCache) GetObject(_ context.Context, bucket, key string) (*storage.Object, bool) {
	cacheKey := fmt.Sprintf("%s/%s", bucket, key)

	// Try hot cache first
	if cached, ok := c.hotCache.Get(cacheKey); ok {
		if time.Now().Before(cached.expiresAt) {
			c.recordHit()

			// Return a reader for the cached data
			return &storage.Object{
				Body:         io.NopCloser(newBytesReader(cached.data)),
				ContentType:  cached.info.ContentType,
				Size:         cached.info.Size,
				ETag:         cached.info.ETag,
				LastModified: cached.info.LastModified,
				Metadata:     cached.info.Metadata,
			}, true
		}

		// Expired, remove from cache
		c.hotCache.Remove(cacheKey)
	}

	c.recordMiss()
	return nil, false
}

// PutObject adds an object to cache if it meets criteria
func (c *ObjectCache) PutObject(_ context.Context, bucket, key string, data []byte, info *storage.ObjectInfo) {
	// Only cache small objects
	if int64(len(data)) > c.maxObjectSize {
		return
	}

	cacheKey := fmt.Sprintf("%s/%s", bucket, key)

	// Add to hot cache
	c.hotCache.Add(cacheKey, &cachedObject{
		data:      data,
		info:      info,
		expiresAt: time.Now().Add(c.ttl),
	})

	// Also update metadata cache
	c.metaCache.Add(cacheKey, info)
}

// GetMetadata retrieves object metadata from cache
func (c *ObjectCache) GetMetadata(_ context.Context, bucket, key string) (*storage.ObjectInfo, bool) {
	cacheKey := fmt.Sprintf("%s/%s", bucket, key)

	if info, ok := c.metaCache.Get(cacheKey); ok {
		c.recordHit()
		return info, true
	}

	c.recordMiss()
	return nil, false
}

// PutMetadata adds object metadata to cache
func (c *ObjectCache) PutMetadata(ctx context.Context, bucket, key string, info *storage.ObjectInfo) {
	cacheKey := fmt.Sprintf("%s/%s", bucket, key)
	c.metaCache.Add(cacheKey, info)
}

// Invalidate removes an object from all caches
func (c *ObjectCache) Invalidate(bucket, key string) {
	cacheKey := fmt.Sprintf("%s/%s", bucket, key)
	c.hotCache.Remove(cacheKey)
	c.metaCache.Remove(cacheKey)
}

// InvalidateBucket removes all objects from a bucket
func (c *ObjectCache) InvalidateBucket(bucket string) {
	// This is a simple implementation - in production you might want
	// to maintain a bucket->keys index for efficient invalidation
	prefix := bucket + "/"

	// Clear hot cache entries
	for _, key := range c.hotCache.Keys() {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			c.hotCache.Remove(key)
		}
	}

	// Clear metadata cache entries
	for _, key := range c.metaCache.Keys() {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			c.metaCache.Remove(key)
		}
	}
}

// Stats returns cache statistics
func (c *ObjectCache) Stats() (hits, misses uint64, hitRate float64) {
	c.mu.RLock()
	hits = c.hits
	misses = c.misses
	c.mu.RUnlock()

	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return hits, misses, hitRate
}

func (c *ObjectCache) recordHit() {
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
}

func (c *ObjectCache) recordMiss() {
	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
}

// bytesReader provides a resettable reader for cached data
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// CachingBackend wraps a storage backend with caching
type CachingBackend struct {
	storage.Backend
	cache *ObjectCache
}

// NewCachingBackend creates a new caching storage backend
func NewCachingBackend(backend storage.Backend, cache *ObjectCache) *CachingBackend {
	return &CachingBackend{
		Backend: backend,
		cache:   cache,
	}
}

// GetObject retrieves an object with caching
func (cb *CachingBackend) GetObject(ctx context.Context, bucket, key string) (*storage.Object, error) {
	// Try cache first
	if obj, ok := cb.cache.GetObject(ctx, bucket, key); ok {
		// logrus.WithFields(logrus.Fields{
		// 	"bucket": bucket,
		// 	"key":    key,
		// }).Debug("Cache hit")
		return obj, nil
	}

	// Cache miss, fetch from backend
	obj, err := cb.Backend.GetObject(ctx, bucket, key)
	if err != nil {
		return nil, err
	}

	// For cacheable objects, read the data and cache it
	if obj.Size > 0 && obj.Size <= cb.cache.maxObjectSize {
		data := make([]byte, obj.Size)
		_, readErr := io.ReadFull(obj.Body, data)
		_ = obj.Body.Close()

		if readErr == nil {
			// Cache the object
			info := &storage.ObjectInfo{
				Key:          key,
				Size:         obj.Size,
				ETag:         obj.ETag,
				LastModified: obj.LastModified,
				ContentType:  obj.ContentType,
				Metadata:     obj.Metadata,
			}
			cb.cache.PutObject(ctx, bucket, key, data, info)

			// Return a new reader
			obj.Body = io.NopCloser(newBytesReader(data))
		} else {
			// Read failed, fetch again
			return cb.Backend.GetObject(ctx, bucket, key)
		}
	}

	return obj, nil
}

// HeadObject retrieves object metadata with caching
func (cb *CachingBackend) HeadObject(ctx context.Context, bucket, key string) (*storage.ObjectInfo, error) {
	// Try cache first
	if info, ok := cb.cache.GetMetadata(ctx, bucket, key); ok {
		return info, nil
	}

	// Cache miss, fetch from backend
	info, err := cb.Backend.HeadObject(ctx, bucket, key)
	if err != nil {
		return nil, err
	}

	// Cache the metadata
	cb.cache.PutMetadata(ctx, bucket, key, info)

	return info, nil
}

// PutObject stores an object and invalidates cache
func (cb *CachingBackend) PutObject(
	ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string,
) error {
	err := cb.Backend.PutObject(ctx, bucket, key, reader, size, metadata)
	if err != nil {
		return err
	}

	// Invalidate cache
	cb.cache.Invalidate(bucket, key)

	return nil
}

// DeleteObject deletes an object and invalidates cache
func (cb *CachingBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	err := cb.Backend.DeleteObject(ctx, bucket, key)
	if err != nil {
		return err
	}

	// Invalidate cache
	cb.cache.Invalidate(bucket, key)

	return nil
}

// DeleteBucket deletes a bucket and invalidates all its cached objects
func (cb *CachingBackend) DeleteBucket(ctx context.Context, bucket string) error {
	err := cb.Backend.DeleteBucket(ctx, bucket)
	if err != nil {
		return err
	}

	// Invalidate all objects in the bucket
	cb.cache.InvalidateBucket(bucket)

	return nil
}
