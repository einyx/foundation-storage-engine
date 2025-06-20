package encryption_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/einyx/s3proxy-go/internal/encryption"
	"github.com/einyx/s3proxy-go/internal/encryption/keys"
	"github.com/einyx/s3proxy-go/internal/encryption/stream"
	"github.com/einyx/s3proxy-go/internal/encryption/types"
)

func TestEncryptionIntegration(t *testing.T) {
	// Generate a random master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	// Create key provider
	keyProvider, err := keys.NewLocalKeyProvider(masterKey)
	require.NoError(t, err)

	// Create encryptor
	encryptor := stream.NewSimpleAESGCMEncryptor(keyProvider)

	// Create encryption manager
	manager := encryption.NewManager(keyProvider, encryptor, true)

	t.Run("EncryptDecryptSmallData", func(t *testing.T) {
		ctx := context.Background()
		originalData := []byte("Hello, World! This is a test of the encryption system.")

		// Encrypt
		reader := bytes.NewReader(originalData)
		encReader, metadata, err := manager.Encrypt(ctx, reader, int64(len(originalData)))
		require.NoError(t, err)
		assert.NotNil(t, metadata)

		// Read encrypted data
		encryptedData, err := io.ReadAll(encReader)
		require.NoError(t, err)
		assert.NotEqual(t, originalData, encryptedData) // Should be different

		// Decrypt
		encReader = bytes.NewReader(encryptedData)
		decReader, err := manager.Decrypt(ctx, encReader, metadata)
		require.NoError(t, err)

		// Read decrypted data
		decryptedData, err := io.ReadAll(decReader)
		require.NoError(t, err)
		assert.Equal(t, originalData, decryptedData)
	})

	t.Run("EncryptDecryptLargeData", func(t *testing.T) {
		ctx := context.Background()

		// Generate 10MB of random data
		originalData := make([]byte, 10*1024*1024)
		_, err := rand.Read(originalData)
		require.NoError(t, err)

		// Encrypt
		reader := bytes.NewReader(originalData)
		encReader, metadata, err := manager.Encrypt(ctx, reader, int64(len(originalData)))
		require.NoError(t, err)

		// Read encrypted data
		encryptedData, err := io.ReadAll(encReader)
		require.NoError(t, err)
		assert.NotEqual(t, originalData, encryptedData)

		// Decrypt
		encReader = bytes.NewReader(encryptedData)
		decReader, err := manager.Decrypt(ctx, encReader, metadata)
		require.NoError(t, err)

		// Read decrypted data
		decryptedData, err := io.ReadAll(decReader)
		require.NoError(t, err)
		assert.Equal(t, originalData, decryptedData)
	})

	t.Run("MetadataHandling", func(t *testing.T) {
		ctx := context.Background()
		data := []byte("Test data")

		// Encrypt
		reader := bytes.NewReader(data)
		_, metadata, err := manager.Encrypt(ctx, reader, int64(len(data)))
		require.NoError(t, err)

		// Check metadata
		assert.Equal(t, "AES-256-GCM", metadata[types.MetadataKeyAlgorithm])
		assert.Equal(t, "local", metadata[types.MetadataKeyID])
		assert.NotEmpty(t, metadata[types.MetadataKeyEncryptedDEK])
		assert.NotEmpty(t, metadata[types.MetadataKeyNonce])
		assert.Equal(t, "9", metadata[types.MetadataKeyEncryptedSize])
	})
}
