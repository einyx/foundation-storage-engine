package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/einyx/s3proxy-go/internal/config"
	"github.com/einyx/s3proxy-go/internal/encryption"
	"github.com/einyx/s3proxy-go/internal/encryption/keys"
	"github.com/einyx/s3proxy-go/internal/encryption/stream"
)

func TestAzureEncryptionIntegration(t *testing.T) {
	// Skip if no Azure credentials
	accountName := os.Getenv("AZURE_STORAGE_ACCOUNT")
	accountKey := os.Getenv("AZURE_STORAGE_KEY")
	if accountName == "" || accountKey == "" {
		t.Skip("Skipping Azure encryption test: AZURE_STORAGE_ACCOUNT or AZURE_STORAGE_KEY not set")
	}

	containerName := os.Getenv("AZURE_CONTAINER_NAME")
	if containerName == "" {
		containerName = "test-encryption-" + time.Now().Format("20060102150405")
	}

	// Generate master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	// Create Azure backend
	azureConfig := &config.AzureStorageConfig{
		AccountName:   accountName,
		AccountKey:    accountKey,
		ContainerName: containerName,
		UseSAS:        false,
	}

	azureBackend, err := NewAzureBackend(azureConfig)
	require.NoError(t, err)

	// Create container
	ctx := context.Background()
	err = azureBackend.CreateBucket(ctx, containerName)
	if err != nil {
		t.Logf("Container creation warning: %v", err)
	}

	// Ensure cleanup
	defer func() {
		// Clean up test objects
		objects, _ := azureBackend.ListObjects(ctx, containerName, "", "", 1000)
		for _, obj := range objects.Contents {
			_ = azureBackend.DeleteObject(ctx, containerName, obj.Key)
		}
	}()

	// Create encryption components
	keyProvider, err := keys.NewLocalKeyProvider(masterKey)
	require.NoError(t, err)

	encryptor := stream.NewSimpleAESGCMEncryptor(keyProvider)
	encryptionManager := encryption.NewManager(keyProvider, encryptor, true)

	// Create encrypted backend
	encryptedBackend := NewEncryptedBackend(azureBackend, encryptionManager)

	t.Run("SmallFileEncryption", func(t *testing.T) {
		data := []byte("Hello Azure with encryption!")
		key := "test/small-encrypted.txt"
		metadata := map[string]string{
			"test": "true",
			"type": "small",
		}

		// Upload encrypted
		err := encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(len(data)), metadata)
		require.NoError(t, err)

		// Download and decrypt
		obj, err := encryptedBackend.GetObject(ctx, containerName, key)
		require.NoError(t, err)
		defer func() { _ = obj.Body.Close() }()

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(obj.Body)
		require.NoError(t, err)

		assert.Equal(t, data, buf.Bytes())
		assert.Equal(t, "true", obj.Metadata["test"])
		assert.Equal(t, "small", obj.Metadata["type"])
		assert.Equal(t, "AES256", obj.Metadata["x-amz-server-side-encryption"])
	})

	t.Run("LargeFileEncryption", func(t *testing.T) {
		// 10MB file
		size := 10 * 1024 * 1024
		data := make([]byte, size)
		_, err := rand.Read(data)
		require.NoError(t, err)

		key := "test/large-encrypted.bin"

		// Upload encrypted
		err = encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(len(data)), nil)
		require.NoError(t, err)

		// Download and decrypt
		obj, err := encryptedBackend.GetObject(ctx, containerName, key)
		require.NoError(t, err)
		defer func() { _ = obj.Body.Close() }()

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(obj.Body)
		require.NoError(t, err)

		assert.Equal(t, len(data), buf.Len())
		assert.Equal(t, data, buf.Bytes())
	})

	t.Run("DirectAccessShowsEncrypted", func(t *testing.T) {
		data := []byte("This should be encrypted")
		key := "test/verify-encrypted.txt"

		// Upload through encrypted backend
		err := encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(len(data)), nil)
		require.NoError(t, err)

		// Read directly through Azure backend
		obj, err := azureBackend.GetObject(ctx, containerName, key)
		require.NoError(t, err)
		defer func() { _ = obj.Body.Close() }()

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(obj.Body)
		require.NoError(t, err)

		// Should NOT match original data (it's encrypted)
		assert.NotEqual(t, data, buf.Bytes())
		assert.NotEmpty(t, obj.Metadata["x-amz-meta-encryption-dek"])
		assert.Equal(t, "AES-256-GCM", obj.Metadata["x-amz-meta-encryption-algorithm"])
	})

	t.Run("BackwardCompatibility", func(t *testing.T) {
		data := []byte("Plain text data")
		key := "test/plain.txt"

		// Upload directly (unencrypted)
		err := azureBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(len(data)), nil)
		require.NoError(t, err)

		// Read through encrypted backend
		obj, err := encryptedBackend.GetObject(ctx, containerName, key)
		require.NoError(t, err)
		defer func() { _ = obj.Body.Close() }()

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(obj.Body)
		require.NoError(t, err)

		// Should match (backward compatible)
		assert.Equal(t, data, buf.Bytes())
	})

	t.Run("ListEncryptedObjects", func(t *testing.T) {
		// Upload a mix of encrypted and plain objects
		plainKey := "test/list/plain.txt"
		encKey := "test/list/encrypted.txt"

		err := azureBackend.PutObject(ctx, containerName, plainKey, bytes.NewReader([]byte("plain")), 5, nil)
		require.NoError(t, err)

		err = encryptedBackend.PutObject(ctx, containerName, encKey, bytes.NewReader([]byte("encrypted")), 9, nil)
		require.NoError(t, err)

		// List through encrypted backend
		result, err := encryptedBackend.ListObjects(ctx, containerName, "test/list/", "", 10)
		require.NoError(t, err)

		// Should find both objects
		assert.GreaterOrEqual(t, len(result.Contents), 2)

		// Find our test objects
		var foundPlain, foundEnc bool
		for _, obj := range result.Contents {
			if obj.Key == plainKey {
				foundPlain = true
				assert.Equal(t, int64(5), obj.Size)
			}
			if obj.Key == encKey {
				foundEnc = true
				// List operations show encrypted size (25) since Azure doesn't include metadata in lists
				assert.Equal(t, int64(25), obj.Size)
			}
		}
		assert.True(t, foundPlain, "Plain object not found")
		assert.True(t, foundEnc, "Encrypted object not found")
	})

	t.Run("HeadEncryptedObject", func(t *testing.T) {
		data := []byte("Test head object")
		key := "test/head-encrypted.txt"
		metadata := map[string]string{
			"content-type": "text/plain",
		}

		// Upload encrypted
		err := encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(len(data)), metadata)
		require.NoError(t, err)

		// Head object
		obj, err := encryptedBackend.HeadObject(ctx, containerName, key)
		require.NoError(t, err)

		assert.Equal(t, int64(len(data)), obj.Size)
		assert.Equal(t, "text/plain", obj.Metadata["content-type"])
		assert.Equal(t, "AES256", obj.Metadata["x-amz-server-side-encryption"])
		assert.NotEmpty(t, obj.LastModified)
	})

	t.Run("DeleteEncryptedObject", func(t *testing.T) {
		key := "test/delete-encrypted.txt"

		// Upload encrypted
		err := encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader([]byte("delete me")), 9, nil)
		require.NoError(t, err)

		// Verify it exists
		_, err = encryptedBackend.HeadObject(ctx, containerName, key)
		require.NoError(t, err)

		// Delete
		err = encryptedBackend.DeleteObject(ctx, containerName, key)
		require.NoError(t, err)

		// Verify it's gone
		_, err = encryptedBackend.HeadObject(ctx, containerName, key)
		assert.Error(t, err)
	})
}

// Benchmark Azure encryption performance
func BenchmarkAzureEncryption(b *testing.B) {
	accountName := os.Getenv("AZURE_STORAGE_ACCOUNT")
	accountKey := os.Getenv("AZURE_STORAGE_KEY")
	if accountName == "" || accountKey == "" {
		b.Skip("Skipping Azure benchmark: credentials not set")
	}

	containerName := "benchmark-encryption"

	// Setup
	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)

	azureConfig := &config.AzureStorageConfig{
		AccountName:   accountName,
		AccountKey:    accountKey,
		ContainerName: containerName,
	}

	azureBackend, _ := NewAzureBackend(azureConfig)
	keyProvider, _ := keys.NewLocalKeyProvider(masterKey)
	encryptor := stream.NewSimpleAESGCMEncryptor(keyProvider)
	encryptionManager := encryption.NewManager(keyProvider, encryptor, true)
	encryptedBackend := NewEncryptedBackend(azureBackend, encryptionManager)

	ctx := context.Background()
	_ = azureBackend.CreateBucket(ctx, containerName)

	// Test data sizes
	sizes := []int{
		1024,        // 1KB
		1024 * 100,  // 100KB
		1024 * 1024, // 1MB
	}

	for _, size := range sizes {
		data := make([]byte, size)
		_, _ = rand.Read(data)

		b.Run(fmt.Sprintf("Upload_%dKB", size/1024), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("bench/upload-%d-%d", size, i)
				err := encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(size), nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// Upload one for download test
		key := fmt.Sprintf("bench/download-%d", size)
		_ = encryptedBackend.PutObject(ctx, containerName, key, bytes.NewReader(data), int64(size), nil)

		b.Run(fmt.Sprintf("Download_%dKB", size/1024), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				obj, err := encryptedBackend.GetObject(ctx, containerName, key)
				if err != nil {
					b.Fatal(err)
				}
				_, _ = io.ReadAll(obj.Body)
				_ = obj.Body.Close()
			}
		})
	}

	// Cleanup
	objects, _ := azureBackend.ListObjects(ctx, containerName, "bench/", "", 1000)
	for _, obj := range objects.Contents {
		_ = azureBackend.DeleteObject(ctx, containerName, obj.Key)
	}
}
