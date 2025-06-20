package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/einyx/s3proxy-go/internal/encryption"
	"github.com/einyx/s3proxy-go/internal/encryption/types"
)

// readCloserWrapper wraps an io.Reader to implement io.ReadCloser
type readCloserWrapper struct {
	io.Reader
}

func (r *readCloserWrapper) Close() error {
	if closer, ok := r.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// multipartUploadInfo stores information about in-progress multipart uploads
type multipartUploadInfo struct {
	bucket           string
	key              string
	originalMetadata map[string]string
}

// EncryptedBackend wraps a storage backend with transparent encryption
type EncryptedBackend struct {
	backend Backend
	manager *encryption.Manager
	// multipartUploads stores info about in-progress multipart uploads
	// Key: uploadID, Value: multipartUploadInfo
	multipartUploads sync.Map
}

// NewEncryptedBackend creates a new encrypted backend wrapper
func NewEncryptedBackend(backend Backend, manager *encryption.Manager) *EncryptedBackend {
	return &EncryptedBackend{
		backend: backend,
		manager: manager,
	}
}

// GetObject retrieves and decrypts an object
func (e *EncryptedBackend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	// Get the object from underlying backend
	obj, err := e.backend.GetObject(ctx, bucket, key)
	if err != nil {
		return nil, err
	}

	// Multipart encrypted objects work the same as regular encrypted objects
	// The encryption metadata is stored during CompleteMultipartUpload

	// Check if object was encrypted and validate metadata
	isEncrypted := obj.Metadata[types.MetadataKeyAlgorithm] != ""
	if isEncrypted {
		if validationErr := validateEncryptionMetadata(obj.Metadata); validationErr != nil {
			_ = obj.Body.Close()
			return nil, validationErr
		}
	}

	// Decrypt the body if needed
	decryptedBody, err := e.manager.Decrypt(ctx, obj.Body, obj.Metadata)
	if err != nil {
		_ = obj.Body.Close()
		return nil, fmt.Errorf("failed to decrypt object: %w", err)
	}

	// Update the object with decrypted body (ensure it's a ReadCloser)
	if rc, ok := decryptedBody.(io.ReadCloser); ok {
		obj.Body = rc
	} else {
		obj.Body = &readCloserWrapper{Reader: decryptedBody}
	}

	// Restore original size for encrypted objects
	if isEncrypted {
		obj.Size = getOriginalSize(obj.Metadata, obj.Size)
	}

	// Remove internal encryption metadata but keep user-friendly markers
	e.cleanMetadata(obj.Metadata)

	// Keep the S3-compatible encryption marker for compatibility
	if isEncrypted {
		obj.Metadata["x-amz-server-side-encryption"] = "AES256"
	}

	return obj, nil
}

// PutObject encrypts and stores an object
func (e *EncryptedBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	// Check if we should encrypt this bucket
	if !e.manager.ShouldEncrypt(bucket) {
		return e.backend.PutObject(ctx, bucket, key, reader, size, metadata)
	}

	// Encrypt the data
	encryptedReader, encMetadata, err := e.manager.Encrypt(ctx, reader, size)
	if err != nil {
		return fmt.Errorf("failed to encrypt object: %w", err)
	}

	// Merge encryption metadata with user metadata
	if metadata == nil {
		metadata = make(map[string]string)
	}
	for k, v := range encMetadata {
		metadata[k] = v
	}

	// Add S3-compatible encryption marker
	metadata["x-amz-server-side-encryption"] = "AES256"

	// Validate encryption was successful
	if err := validateEncryptionMetadata(encMetadata); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Calculate encrypted size from the reader or fallback
	encryptedSize := calculateEncryptedSize(encryptedReader, size)

	// Store the encrypted object directly
	return e.backend.PutObject(ctx, bucket, key, encryptedReader, encryptedSize, metadata)
}

// DeleteObject delegates to the underlying backend
func (e *EncryptedBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	return e.backend.DeleteObject(ctx, bucket, key)
}

// ListObjects delegates to the underlying backend and cleans metadata
func (e *EncryptedBackend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	result, err := e.backend.ListObjects(ctx, bucket, prefix, marker, maxKeys)
	if err != nil {
		return nil, err
	}

	// Clean encryption metadata from results
	for i := range result.Contents {
		if result.Contents[i].Metadata != nil {
			e.processListItem(&result.Contents[i])
		}
	}

	return result, nil
}

// ListObjectsWithDelimiter delegates to the underlying backend
func (e *EncryptedBackend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	result, err := e.backend.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, delimiter, maxKeys)
	if err != nil {
		return nil, err
	}

	// Clean encryption metadata from results
	for i := range result.Contents {
		if result.Contents[i].Metadata != nil {
			e.processListItem(&result.Contents[i])
		}
	}

	return result, nil
}

// HeadObject retrieves object metadata and cleans encryption info
func (e *EncryptedBackend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	info, err := e.backend.HeadObject(ctx, bucket, key)
	if err != nil {
		return nil, err
	}

	// Check if object was encrypted and process metadata
	isEncrypted := info.Metadata[types.MetadataKeyAlgorithm] != ""
	if isEncrypted {
		info.Size = getOriginalSize(info.Metadata, info.Size)
	}
	e.cleanMetadata(info.Metadata)
	if isEncrypted {
		info.Metadata["x-amz-server-side-encryption"] = "AES256"
	}

	return info, nil
}

// ListBuckets returns a list of all buckets.
func (e *EncryptedBackend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	return e.backend.ListBuckets(ctx)
}

func (e *EncryptedBackend) CreateBucket(ctx context.Context, bucket string) error {
	return e.backend.CreateBucket(ctx, bucket)
}

func (e *EncryptedBackend) DeleteBucket(ctx context.Context, bucket string) error {
	return e.backend.DeleteBucket(ctx, bucket)
}

func (e *EncryptedBackend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	return e.backend.BucketExists(ctx, bucket)
}

func (e *EncryptedBackend) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	return e.backend.GetObjectACL(ctx, bucket, key)
}

func (e *EncryptedBackend) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	return e.backend.PutObjectACL(ctx, bucket, key, acl)
}

func (e *EncryptedBackend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	if !e.manager.IsEnabled() {
		return e.backend.InitiateMultipartUpload(ctx, bucket, key, metadata)
	}

	// For encrypted multipart uploads, we need to handle it differently
	// We'll store the parts unencrypted and encrypt the final object after assembly
	// Mark this as an encrypted multipart upload
	if metadata == nil {
		metadata = make(map[string]string)
	}

	uploadID, err := e.backend.InitiateMultipartUpload(ctx, bucket, key, metadata)
	if err != nil {
		return "", err
	}

	// Store info about this multipart upload
	e.multipartUploads.Store(uploadID, multipartUploadInfo{
		bucket:           bucket,
		key:              key,
		originalMetadata: metadata,
	})

	return uploadID, nil
}

func (e *EncryptedBackend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	if !e.manager.IsEnabled() {
		return e.backend.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, size)
	}

	// For now, multipart uploads store parts without encryption
	// The entire object will be encrypted during CompleteMultipartUpload
	// This is a temporary approach - proper implementation would encrypt each part
	return e.backend.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, size)
}

func (e *EncryptedBackend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	if !e.manager.IsEnabled() {
		return e.backend.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
	}

	// Retrieve upload info
	val, ok := e.multipartUploads.Load(uploadID)
	if !ok {
		// If no info stored, just complete without encryption
		return e.backend.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
	}

	uploadInfo := val.(multipartUploadInfo)

	// Complete the multipart upload first
	err := e.backend.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
	if err != nil {
		return err
	}

	// Now we need to encrypt the completed object
	// Get the assembled object
	obj, err := e.backend.GetObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("failed to get completed object for encryption: %w", err)
	}
	defer func() { _ = obj.Body.Close() }()

	// Read the entire object
	data, err := io.ReadAll(obj.Body)
	if err != nil {
		return fmt.Errorf("failed to read completed object: %w", err)
	}

	// Encrypt the data
	encReader, encMetadata, err := e.manager.Encrypt(ctx, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to encrypt completed object: %w", err)
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(encReader)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Merge metadata: original metadata + encryption metadata
	metadata := make(map[string]string)

	// First, copy original metadata from initiate
	for k, v := range uploadInfo.originalMetadata {
		metadata[k] = v
	}

	// Then add any metadata from the completed object
	for k, v := range obj.Metadata {
		metadata[k] = v
	}

	// Finally, add encryption metadata
	for k, v := range encMetadata {
		metadata[k] = v
	}

	// Add S3-compatible encryption marker
	metadata["x-amz-server-side-encryption"] = "AES256"

	// Replace the object with encrypted version
	err = e.backend.PutObject(ctx, bucket, key, bytes.NewReader(encryptedData), int64(len(encryptedData)), metadata)
	if err != nil {
		return fmt.Errorf("failed to store encrypted object: %w", err)
	}

	// Clean up stored upload info
	e.multipartUploads.Delete(uploadID)

	return nil
}

func (e *EncryptedBackend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	// Clean up stored upload info if present
	e.multipartUploads.Delete(uploadID)
	return e.backend.AbortMultipartUpload(ctx, bucket, key, uploadID)
}

func (e *EncryptedBackend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	return e.backend.ListParts(ctx, bucket, key, uploadID, maxParts, partNumberMarker)
}

// cleanMetadata removes encryption-related metadata from user-visible metadata
func (e *EncryptedBackend) cleanMetadata(metadata map[string]string) {
	delete(metadata, types.MetadataKeyAlgorithm)
	delete(metadata, types.MetadataKeyID)
	delete(metadata, types.MetadataKeyEncryptedDEK)
	delete(metadata, types.MetadataKeyNonce)
	delete(metadata, types.MetadataKeyEncryptedSize)
}

// validateEncryptionMetadata ensures all required encryption metadata is present
func validateEncryptionMetadata(metadata map[string]string) error {
	requiredKeys := map[string]string{
		types.MetadataKeyAlgorithm:    "algorithm",
		types.MetadataKeyEncryptedDEK: "DEK",
		types.MetadataKeyNonce:        "nonce",
	}

	for key, name := range requiredKeys {
		if metadata[key] == "" {
			return fmt.Errorf("missing %s metadata", name)
		}
	}
	return nil
}

// calculateEncryptedSize determines the encrypted data size from reader or calculates fallback
func calculateEncryptedSize(encryptedReader io.Reader, originalSize int64) int64 {
	if br, ok := encryptedReader.(*bytes.Reader); ok {
		return int64(br.Len())
	}
	// Fallback: AES-GCM overhead is 16 bytes (tag only, nonce in metadata)
	return originalSize + 16
}

// getOriginalSize extracts the original size from metadata or returns current size
func getOriginalSize(metadata map[string]string, currentSize int64) int64 {
	if sizeStr := metadata[types.MetadataKeyEncryptedSize]; sizeStr != "" {
		if originalSize, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			return originalSize
		}
	}
	return currentSize
}

// processListItem handles encryption metadata cleanup for list operations
func (e *EncryptedBackend) processListItem(item *ObjectInfo) {
	isEncrypted := item.Metadata[types.MetadataKeyAlgorithm] != ""
	if isEncrypted {
		item.Size = getOriginalSize(item.Metadata, item.Size)
	}
	e.cleanMetadata(item.Metadata)
	if isEncrypted {
		item.Metadata["x-amz-server-side-encryption"] = "AES256"
	}
}
