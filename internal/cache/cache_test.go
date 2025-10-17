package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/storage"
)

func TestNewObjectCache(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create object cache: %v", err)
	}

	if cache == nil {
		t.Fatal("Cache should not be nil")
	}

	if cache.maxMemory != 1024*1024 {
		t.Errorf("Expected max memory 1MB, got %d", cache.maxMemory)
	}

	if cache.maxObjectSize != 64*1024 {
		t.Errorf("Expected max object size 64KB, got %d", cache.maxObjectSize)
	}

	if cache.ttl != 5*time.Minute {
		t.Errorf("Expected TTL 5m, got %v", cache.ttl)
	}
}

func TestNewObjectCache_SmallMemory(t *testing.T) {
	// Test with very small memory to trigger minimum cache size
	cache, err := NewObjectCache(100, 10, time.Minute)
	if err != nil {
		t.Fatalf("Failed to create object cache: %v", err)
	}

	// Should create cache with minimum size
	if cache == nil {
		t.Fatal("Cache should not be nil")
	}
}

func TestObjectCache_PutGetObject(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data content")

	info := &storage.ObjectInfo{
		Key:          key,
		Size:         int64(len(data)),
		ETag:         "test-etag",
		LastModified: time.Now(),
		ContentType:  "text/plain",
		Metadata:     map[string]string{"custom": "value"},
	}

	// Put object in cache
	cache.PutObject(ctx, bucket, key, data, info)

	// Get object from cache
	obj, found := cache.GetObject(ctx, bucket, key)
	if !found {
		t.Fatal("Object should be found in cache")
	}

	if obj == nil {
		t.Fatal("Object should not be nil")
	}

	// Read the cached data
	cachedData, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("Failed to read cached data: %v", err)
	}

	if string(cachedData) != string(data) {
		t.Errorf("Expected cached data %s, got %s", string(data), string(cachedData))
	}

	if obj.ContentType != info.ContentType {
		t.Errorf("Expected content type %s, got %s", info.ContentType, obj.ContentType)
	}

	if obj.Size != info.Size {
		t.Errorf("Expected size %d, got %d", info.Size, obj.Size)
	}

	if obj.ETag != info.ETag {
		t.Errorf("Expected ETag %s, got %s", info.ETag, obj.ETag)
	}
}

func TestObjectCache_PutGetObject_TooLarge(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 100, 5*time.Minute) // 100 byte limit
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := make([]byte, 200) // Larger than limit

	info := &storage.ObjectInfo{
		Key:  key,
		Size: int64(len(data)),
	}

	// Put large object - should be ignored
	cache.PutObject(ctx, bucket, key, data, info)

	// Should not be found in cache
	_, found := cache.GetObject(ctx, bucket, key)
	if found {
		t.Error("Large object should not be cached")
	}
}

func TestObjectCache_Expiration(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 10*time.Millisecond) // Very short TTL
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")

	info := &storage.ObjectInfo{
		Key:  key,
		Size: int64(len(data)),
	}

	// Put object
	cache.PutObject(ctx, bucket, key, data, info)

	// Should be found immediately
	_, found := cache.GetObject(ctx, bucket, key)
	if !found {
		t.Error("Object should be found immediately")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should not be found after expiration
	_, found = cache.GetObject(ctx, bucket, key)
	if found {
		t.Error("Object should be expired and removed")
	}
}

func TestObjectCache_Metadata(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"

	info := &storage.ObjectInfo{
		Key:          key,
		Size:         1024,
		ETag:         "test-etag",
		LastModified: time.Now(),
		ContentType:  "application/json",
		Metadata:     map[string]string{"version": "1.0"},
	}

	// Put metadata
	cache.PutMetadata(ctx, bucket, key, info)

	// Get metadata
	cachedInfo, found := cache.GetMetadata(ctx, bucket, key)
	if !found {
		t.Fatal("Metadata should be found in cache")
	}

	if cachedInfo.Key != info.Key {
		t.Errorf("Expected key %s, got %s", info.Key, cachedInfo.Key)
	}

	if cachedInfo.Size != info.Size {
		t.Errorf("Expected size %d, got %d", info.Size, cachedInfo.Size)
	}

	if cachedInfo.ContentType != info.ContentType {
		t.Errorf("Expected content type %s, got %s", info.ContentType, cachedInfo.ContentType)
	}
}

func TestObjectCache_Invalidate(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")

	info := &storage.ObjectInfo{
		Key:  key,
		Size: int64(len(data)),
	}

	// Put object and metadata
	cache.PutObject(ctx, bucket, key, data, info)
	cache.PutMetadata(ctx, bucket, key, info)

	// Verify they exist
	_, found := cache.GetObject(ctx, bucket, key)
	if !found {
		t.Error("Object should be found before invalidation")
	}

	_, found = cache.GetMetadata(ctx, bucket, key)
	if !found {
		t.Error("Metadata should be found before invalidation")
	}

	// Invalidate
	cache.Invalidate(bucket, key)

	// Should not be found after invalidation
	_, found = cache.GetObject(ctx, bucket, key)
	if found {
		t.Error("Object should not be found after invalidation")
	}

	_, found = cache.GetMetadata(ctx, bucket, key)
	if found {
		t.Error("Metadata should not be found after invalidation")
	}
}

func TestObjectCache_InvalidateBucket(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"
	otherBucket := "other-bucket"

	// Add objects to different buckets
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		data := []byte(fmt.Sprintf("data-%d", i))
		info := &storage.ObjectInfo{Key: key, Size: int64(len(data))}

		cache.PutObject(ctx, bucket, key, data, info)
		cache.PutObject(ctx, otherBucket, key, data, info)
	}

	// Invalidate one bucket
	cache.InvalidateBucket(bucket)

	// Objects from the invalidated bucket should not be found
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := cache.GetObject(ctx, bucket, key)
		if found {
			t.Errorf("Object %s should not be found in invalidated bucket", key)
		}

		// Objects from other bucket should still exist
		_, found = cache.GetObject(ctx, otherBucket, key)
		if !found {
			t.Errorf("Object %s should still be found in other bucket", key)
		}
	}
}

func TestObjectCache_Stats(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	ctx := context.Background()
	bucket := "test-bucket"

	// Initial stats should be zero
	hits, misses, hitRate := cache.Stats()
	if hits != 0 || misses != 0 || hitRate != 0 {
		t.Errorf("Initial stats should be zero, got hits=%d, misses=%d, hitRate=%f", hits, misses, hitRate)
	}

	// Cache miss
	_, found := cache.GetObject(ctx, bucket, "nonexistent")
	if found {
		t.Error("Should not find nonexistent object")
	}

	hits, misses, hitRate = cache.Stats()
	if hits != 0 || misses != 1 {
		t.Errorf("Expected 0 hits, 1 miss, got hits=%d, misses=%d", hits, misses)
	}

	// Add an object
	data := []byte("test")
	info := &storage.ObjectInfo{Key: "test", Size: int64(len(data))}
	cache.PutObject(ctx, bucket, "test", data, info)

	// Cache hit
	_, found = cache.GetObject(ctx, bucket, "test")
	if !found {
		t.Error("Should find cached object")
	}

	hits, misses, hitRate = cache.Stats()
	if hits != 1 || misses != 1 {
		t.Errorf("Expected 1 hit, 1 miss, got hits=%d, misses=%d", hits, misses)
	}

	expectedHitRate := 0.5
	if hitRate != expectedHitRate {
		t.Errorf("Expected hit rate %f, got %f", expectedHitRate, hitRate)
	}
}

func TestBytesReader(t *testing.T) {
	data := []byte("hello world")
	reader := newBytesReader(data)

	// Read partial data
	buf := make([]byte, 5)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected to read 5 bytes, got %d", n)
	}
	if string(buf) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(buf))
	}

	// Read remaining data
	buf = make([]byte, 10)
	n, err = reader.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 6 {
		t.Errorf("Expected to read 6 bytes, got %d", n)
	}
	if string(buf[:n]) != " world" {
		t.Errorf("Expected ' world', got '%s'", string(buf[:n]))
	}

	// Read beyond end
	n, err = reader.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF, got %v", err)
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes, got %d", n)
	}
}

// Mock backend for testing
type mockBackend struct {
	objects map[string]*storage.Object
	info    map[string]*storage.ObjectInfo
	errors  map[string]error
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		objects: make(map[string]*storage.Object),
		info:    make(map[string]*storage.ObjectInfo),
		errors:  make(map[string]error),
	}
}

func (m *mockBackend) GetObject(ctx context.Context, bucket, key string) (*storage.Object, error) {
	k := bucket + "/" + key
	if err, exists := m.errors[k]; exists {
		return nil, err
	}
	if obj, exists := m.objects[k]; exists {
		return obj, nil
	}
	return nil, errors.New("object not found")
}

func (m *mockBackend) HeadObject(ctx context.Context, bucket, key string) (*storage.ObjectInfo, error) {
	k := bucket + "/" + key
	if err, exists := m.errors[k]; exists {
		return nil, err
	}
	if info, exists := m.info[k]; exists {
		return info, nil
	}
	return nil, errors.New("object not found")
}

func (m *mockBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	k := bucket + "/" + key
	if err, exists := m.errors[k]; exists {
		return err
	}
	// Simulate storing the object
	return nil
}

func (m *mockBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	k := bucket + "/" + key
	if err, exists := m.errors[k]; exists {
		return err
	}
	delete(m.objects, k)
	delete(m.info, k)
	return nil
}

func (m *mockBackend) DeleteBucket(ctx context.Context, bucket string) error {
	if err, exists := m.errors[bucket]; exists {
		return err
	}
	// Remove all objects from bucket
	for k := range m.objects {
		if strings.HasPrefix(k, bucket+"/") {
			delete(m.objects, k)
		}
	}
	return nil
}

func (m *mockBackend) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	return nil, nil
}

func (m *mockBackend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	return true, nil
}

func (m *mockBackend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*storage.ListObjectsResult, error) {
	return &storage.ListObjectsResult{}, nil
}

func (m *mockBackend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*storage.ListObjectsResult, error) {
	return &storage.ListObjectsResult{}, nil
}

func (m *mockBackend) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*storage.ListObjectsResult, error) {
	return &storage.ListObjectsResult{}, nil
}

func (m *mockBackend) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	return nil
}

func (m *mockBackend) GetObjectACL(ctx context.Context, bucket, key string) (*storage.ACL, error) {
	return nil, nil
}

func (m *mockBackend) PutObjectACL(ctx context.Context, bucket, key string, acl *storage.ACL) error {
	return nil
}

func (m *mockBackend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "upload-id", nil
}

func (m *mockBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	return "etag", nil
}

func (m *mockBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []storage.CompletedPart) error {
	return nil
}

func (m *mockBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return nil
}

func (m *mockBackend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*storage.ListPartsResult, error) {
	return &storage.ListPartsResult{}, nil
}

func (m *mockBackend) CreateBucket(ctx context.Context, bucket string) error {
	return nil
}

func TestCachingBackend_GetObject_CacheHit(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	backend := newMockBackend()
	cachingBackend := NewCachingBackend(backend, cache)

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("cached data")

	// Pre-populate cache
	info := &storage.ObjectInfo{
		Key:         key,
		Size:        int64(len(data)),
		ContentType: "text/plain",
	}
	cache.PutObject(ctx, bucket, key, data, info)

	// Get object - should come from cache
	obj, err := cachingBackend.GetObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	cachedData, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}

	if string(cachedData) != string(data) {
		t.Errorf("Expected cached data %s, got %s", string(data), string(cachedData))
	}
}

func TestCachingBackend_GetObject_CacheMiss(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	backend := newMockBackend()
	cachingBackend := NewCachingBackend(backend, cache)

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("backend data")

	// Add object to backend
	backend.objects[bucket+"/"+key] = &storage.Object{
		Body:        io.NopCloser(strings.NewReader(string(data))),
		Size:        int64(len(data)),
		ContentType: "text/plain",
	}

	// Get object - should come from backend and be cached
	obj, err := cachingBackend.GetObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	backendData, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}

	if string(backendData) != string(data) {
		t.Errorf("Expected backend data %s, got %s", string(data), string(backendData))
	}

	// Verify it was cached
	_, found := cache.GetObject(ctx, bucket, key)
	if !found {
		t.Error("Object should be cached after backend fetch")
	}
}

func TestCachingBackend_HeadObject(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	backend := newMockBackend()
	cachingBackend := NewCachingBackend(backend, cache)

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"

	info := &storage.ObjectInfo{
		Key:         key,
		Size:        1024,
		ContentType: "application/json",
		ETag:        "test-etag",
	}

	// Add to backend
	backend.info[bucket+"/"+key] = info

	// First call - should come from backend and be cached
	result, err := cachingBackend.HeadObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Key != info.Key {
		t.Errorf("Expected key %s, got %s", info.Key, result.Key)
	}

	// Second call - should come from cache
	result2, err := cachingBackend.HeadObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result2.Key != info.Key {
		t.Errorf("Expected cached key %s, got %s", info.Key, result2.Key)
	}
}

func TestCachingBackend_PutObject_InvalidatesCache(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	backend := newMockBackend()
	cachingBackend := NewCachingBackend(backend, cache)

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("old data")

	// Pre-populate cache
	info := &storage.ObjectInfo{Key: key, Size: int64(len(data))}
	cache.PutObject(ctx, bucket, key, data, info)

	// Verify object is cached
	_, found := cache.GetObject(ctx, bucket, key)
	if !found {
		t.Error("Object should be cached initially")
	}

	// Put new object - should invalidate cache
	newData := strings.NewReader("new data")
	err = cachingBackend.PutObject(ctx, bucket, key, newData, 8, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify cache is invalidated
	_, found = cache.GetObject(ctx, bucket, key)
	if found {
		t.Error("Object should be invalidated from cache after put")
	}
}

func TestCachingBackend_DeleteObject_InvalidatesCache(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	backend := newMockBackend()
	cachingBackend := NewCachingBackend(backend, cache)

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")

	// Pre-populate cache
	info := &storage.ObjectInfo{Key: key, Size: int64(len(data))}
	cache.PutObject(ctx, bucket, key, data, info)

	// Delete object - should invalidate cache
	err = cachingBackend.DeleteObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify cache is invalidated
	_, found := cache.GetObject(ctx, bucket, key)
	if found {
		t.Error("Object should be invalidated from cache after delete")
	}
}

func TestCachingBackend_DeleteBucket_InvalidatesCache(t *testing.T) {
	cache, err := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	backend := newMockBackend()
	cachingBackend := NewCachingBackend(backend, cache)

	ctx := context.Background()
	bucket := "test-bucket"

	// Pre-populate cache with multiple objects
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		data := []byte(fmt.Sprintf("data-%d", i))
		info := &storage.ObjectInfo{Key: key, Size: int64(len(data))}
		cache.PutObject(ctx, bucket, key, data, info)
	}

	// Delete bucket - should invalidate all cached objects
	err = cachingBackend.DeleteBucket(ctx, bucket)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify all objects are invalidated
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := cache.GetObject(ctx, bucket, key)
		if found {
			t.Errorf("Object %s should be invalidated from cache after bucket delete", key)
		}
	}
}

func BenchmarkObjectCache_GetObject(b *testing.B) {
	cache, _ := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	data := []byte("benchmark data")
	info := &storage.ObjectInfo{Key: key, Size: int64(len(data))}

	cache.PutObject(ctx, bucket, key, data, info)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.GetObject(ctx, bucket, key)
	}
}

func BenchmarkObjectCache_PutObject(b *testing.B) {
	cache, _ := NewObjectCache(1024*1024, 64*1024, 5*time.Minute)
	ctx := context.Background()
	bucket := "test-bucket"
	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i)
		info := &storage.ObjectInfo{Key: key, Size: int64(len(data))}
		cache.PutObject(ctx, bucket, key, data, info)
	}
}