package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/einyx/s3proxy-go/internal/config"
	"github.com/einyx/s3proxy-go/internal/encryption"
	"github.com/einyx/s3proxy-go/internal/storage"
)

func TestEncryptedBackendIntegration(t *testing.T) {
	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "encrypted-backend-test-*")
	require.NoError(t, err)
	defer func() {
		if cleanErr := os.RemoveAll(tempDir); cleanErr != nil {
			t.Logf("Failed to clean up temp dir: %v", cleanErr)
		}
	}()

	// Generate master key
	masterKey := make([]byte, 32)
	_, err = rand.Read(masterKey)
	require.NoError(t, err)

	// Create filesystem backend
	fsConfig := &config.FileSystemConfig{
		BaseDir: tempDir,
	}
	fsBackend, err := storage.NewFileSystemBackend(fsConfig)
	require.NoError(t, err)

	// Create encryption manager
	encConfig := &config.EncryptionConfig{
		Enabled:     true,
		Algorithm:   "AES-256-GCM",
		KeyProvider: "local",
		Local: &config.LocalKeyConfig{
			MasterKey: base64.StdEncoding.EncodeToString(masterKey),
		},
	}

	ctx := context.Background()
	encManager, err := encryption.NewFromConfig(ctx, encConfig)
	require.NoError(t, err)

	// Create encrypted backend
	backend := storage.NewEncryptedBackend(fsBackend, encManager)

	t.Run("PutAndGetObject", func(t *testing.T) {
		testData := []byte("This is test data for encryption")
		bucket := "test-bucket"
		key := "test-object.txt"

		// Put object
		err := backend.PutObject(ctx, bucket, key, bytes.NewReader(testData), int64(len(testData)), map[string]string{
			"Content-Type": "text/plain",
			"X-Custom":     "metadata",
		})
		require.NoError(t, err)

		// Verify raw file is encrypted
		rawPath := filepath.Join(tempDir, bucket, key)
		rawData, err := os.ReadFile(rawPath)
		require.NoError(t, err)
		assert.NotContains(t, string(rawData), "test data", "Raw file should be encrypted")

		// Get object
		obj, err := backend.GetObject(ctx, bucket, key)
		require.NoError(t, err)
		defer func() {
			if closeErr := obj.Body.Close(); closeErr != nil {
				t.Logf("Failed to close body: %v", closeErr)
			}
		}()

		// Read and verify data
		retrievedData, err := io.ReadAll(obj.Body)
		require.NoError(t, err)
		assert.Equal(t, testData, retrievedData)

		// Verify metadata
		assert.Equal(t, "text/plain", obj.ContentType)
		assert.Equal(t, "metadata", obj.Metadata["X-Custom"])

		// Ensure internal encryption metadata is not visible
		for k := range obj.Metadata {
			assert.NotContains(t, strings.ToLower(k), "encrypted-", "Internal encryption metadata should be hidden")
			assert.NotContains(t, strings.ToLower(k), "nonce", "Internal encryption metadata should be hidden")
			assert.NotContains(t, strings.ToLower(k), "algorithm", "Internal encryption metadata should be hidden")
		}

		// But S3-compatible encryption marker should be present
		assert.Equal(t, "AES256", obj.Metadata["x-amz-server-side-encryption"], "S3-compatible encryption marker should be present")
	})

	t.Run("ListObjects", func(t *testing.T) {
		bucket := "list-bucket"

		// Create multiple objects
		for i := 1; i <= 3; i++ {
			data := []byte(fmt.Sprintf("File %d content", i))
			key := fmt.Sprintf("file-%d.txt", i)

			err := backend.PutObject(ctx, bucket, key, bytes.NewReader(data), int64(len(data)), nil)
			require.NoError(t, err)
		}

		// List objects
		result, err := backend.ListObjects(ctx, bucket, "", "", 10)
		require.NoError(t, err)
		assert.Len(t, result.Contents, 3)

		// Verify sizes are original sizes (not encrypted)
		for _, obj := range result.Contents {
			assert.Less(t, obj.Size, int64(50), "Size should be original, not encrypted")

			// Ensure no internal encryption metadata in listing
			for k := range obj.Metadata {
				assert.NotContains(t, strings.ToLower(k), "encrypted-", "Internal encryption metadata should be hidden")
				assert.NotContains(t, strings.ToLower(k), "nonce", "Internal encryption metadata should be hidden")
				assert.NotContains(t, strings.ToLower(k), "algorithm", "Internal encryption metadata should be hidden")
			}

			// But S3-compatible encryption marker should be present
			assert.Equal(t, "AES256", obj.Metadata["x-amz-server-side-encryption"], "S3-compatible encryption marker should be present")
		}
	})

	t.Run("HeadObject", func(t *testing.T) {
		bucket := "head-bucket"
		key := "head-object.txt"
		testData := []byte("Head object test data")

		// Put object
		err := backend.PutObject(ctx, bucket, key, bytes.NewReader(testData), int64(len(testData)), map[string]string{
			"Content-Type": "application/json",
		})
		require.NoError(t, err)

		// Head object
		info, err := backend.HeadObject(ctx, bucket, key)
		require.NoError(t, err)

		// Verify size is original size
		assert.Equal(t, int64(len(testData)), info.Size)
		assert.Equal(t, "application/json", info.ContentType)

		// Ensure no internal encryption metadata
		for k := range info.Metadata {
			assert.NotContains(t, strings.ToLower(k), "encrypted-", "Internal encryption metadata should be hidden")
			assert.NotContains(t, strings.ToLower(k), "nonce", "Internal encryption metadata should be hidden")
			assert.NotContains(t, strings.ToLower(k), "algorithm", "Internal encryption metadata should be hidden")
		}

		// But S3-compatible encryption marker should be present
		assert.Equal(t, "AES256", info.Metadata["x-amz-server-side-encryption"], "S3-compatible encryption marker should be present")
	})

	t.Run("DeleteObject", func(t *testing.T) {
		bucket := "delete-bucket"
		key := "delete-object.txt"

		// Put object
		err := backend.PutObject(ctx, bucket, key, bytes.NewReader([]byte("delete me")), 9, nil)
		require.NoError(t, err)

		// Verify files exist
		rawPath := filepath.Join(tempDir, bucket, key)
		metaPath := rawPath + ".meta"
		_, err = os.Stat(rawPath)
		require.NoError(t, err)
		_, err = os.Stat(metaPath)
		require.NoError(t, err)

		// Delete object
		err = backend.DeleteObject(ctx, bucket, key)
		require.NoError(t, err)

		// Verify both files are deleted
		_, err = os.Stat(rawPath)
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(metaPath)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("LargeObject", func(t *testing.T) {
		bucket := "large-bucket"
		key := "large-object.bin"

		// Create 5MB of random data
		largeData := make([]byte, 5*1024*1024)
		_, err := rand.Read(largeData)
		require.NoError(t, err)

		// Put large object
		err = backend.PutObject(ctx, bucket, key, bytes.NewReader(largeData), int64(len(largeData)), nil)
		require.NoError(t, err)

		// Get large object
		obj, err := backend.GetObject(ctx, bucket, key)
		require.NoError(t, err)
		defer func() {
			if closeErr := obj.Body.Close(); closeErr != nil {
				t.Logf("Failed to close body: %v", closeErr)
			}
		}()

		// Verify data
		retrievedData, err := io.ReadAll(obj.Body)
		require.NoError(t, err)
		assert.Equal(t, largeData, retrievedData)
	})

	t.Run("NonEncryptedBackwardCompatibility", func(t *testing.T) {
		bucket := "compat-bucket"
		key := "plain.txt"
		plainData := []byte("This is plain text")

		// Put directly through filesystem backend (no encryption)
		err := fsBackend.PutObject(ctx, bucket, key, bytes.NewReader(plainData), int64(len(plainData)), nil)
		require.NoError(t, err)

		// Get through encrypted backend (should work)
		obj, err := backend.GetObject(ctx, bucket, key)
		require.NoError(t, err)
		defer func() {
			if closeErr := obj.Body.Close(); closeErr != nil {
				t.Logf("Failed to close body: %v", closeErr)
			}
		}()

		retrievedData, err := io.ReadAll(obj.Body)
		require.NoError(t, err)
		assert.Equal(t, plainData, retrievedData)
	})
}

func TestEncryptedBackendWithDisabledEncryption(t *testing.T) {
	// Test that encrypted backend works transparently when encryption is disabled
	tempDir, err := os.MkdirTemp("", "encrypted-backend-disabled-*")
	require.NoError(t, err)
	defer func() {
		if cleanErr := os.RemoveAll(tempDir); cleanErr != nil {
			t.Logf("Failed to clean up temp dir: %v", cleanErr)
		}
	}()

	// Create filesystem backend
	fsConfig := &config.FileSystemConfig{
		BaseDir: tempDir,
	}
	fsBackend, err := storage.NewFileSystemBackend(fsConfig)
	require.NoError(t, err)

	// Create disabled encryption manager
	encConfig := &config.EncryptionConfig{
		Enabled: false,
	}

	ctx := context.Background()
	encManager, err := encryption.NewFromConfig(ctx, encConfig)
	require.NoError(t, err)

	// Create encrypted backend (but encryption is disabled)
	backend := storage.NewEncryptedBackend(fsBackend, encManager)

	// Test that it works like a normal backend
	testData := []byte("This should not be encrypted")
	bucket := "test-bucket"
	key := "test.txt"

	err = backend.PutObject(ctx, bucket, key, bytes.NewReader(testData), int64(len(testData)), nil)
	require.NoError(t, err)

	// Verify raw file is NOT encrypted
	rawPath := filepath.Join(tempDir, bucket, key)
	rawData, err := os.ReadFile(rawPath)
	require.NoError(t, err)
	assert.Equal(t, testData, rawData, "Data should not be encrypted when encryption is disabled")
}
