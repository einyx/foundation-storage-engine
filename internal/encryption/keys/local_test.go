package keys

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalKeyProvider(t *testing.T) {
	// Generate a random master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	provider, err := NewLocalKeyProvider(masterKey)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	t.Run("GenerateDEK", func(t *testing.T) {
		ctx := context.Background()

		// Generate a DEK
		dek, encryptedDEK, err := provider.GenerateDEK(ctx)
		require.NoError(t, err)
		assert.Len(t, dek, 32) // 256-bit key
		assert.NotEmpty(t, encryptedDEK)

		// Generate another DEK - should be different
		dek2, encryptedDEK2, err := provider.GenerateDEK(ctx)
		require.NoError(t, err)
		assert.NotEqual(t, dek, dek2)
		assert.NotEqual(t, encryptedDEK, encryptedDEK2)
	})

	t.Run("DecryptDEK", func(t *testing.T) {
		ctx := context.Background()

		// Generate a DEK
		originalDEK, encryptedDEK, err := provider.GenerateDEK(ctx)
		require.NoError(t, err)

		// Decrypt it
		decryptedDEK, err := provider.DecryptDEK(ctx, encryptedDEK)
		require.NoError(t, err)
		assert.Equal(t, originalDEK, decryptedDEK)
	})

	t.Run("InvalidMasterKeySize", func(t *testing.T) {
		_, err := NewLocalKeyProvider([]byte("too-short"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("InvalidEncryptedDEK", func(t *testing.T) {
		ctx := context.Background()

		// Try to decrypt invalid base64
		_, err := provider.DecryptDEK(ctx, "not-base64!")
		assert.Error(t, err)

		// Try to decrypt invalid ciphertext
		_, err = provider.DecryptDEK(ctx, "dG9vLXNob3J0")
		assert.Error(t, err)
	})

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "local", provider.Name())
	})
}
