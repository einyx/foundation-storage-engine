package encryption

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/einyx/s3proxy-go/internal/encryption/types"
	"github.com/einyx/s3proxy-go/internal/kms"
)

// KMSKeyProviderAdapter adapts a KMS provider to the encryption key provider interface
type KMSKeyProviderAdapter struct {
	provider kms.Provider
}

// NewKMSKeyProviderAdapter creates a new adapter
func NewKMSKeyProviderAdapter(provider kms.Provider) types.KeyProvider {
	return &KMSKeyProviderAdapter{
		provider: provider,
	}
}

// GenerateDEK generates a data encryption key
func (a *KMSKeyProviderAdapter) GenerateDEK(ctx context.Context) (key []byte, encryptedKey string, err error) {
	// Use a default key ID - in production this should come from configuration
	// or be passed as a parameter
	keyID := "default"

	dataKey, err := a.provider.GenerateDataKey(ctx, keyID, "AES_256")
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate data key: %w", err)
	}

	// Encode the ciphertext blob as base64 for storage as string
	encryptedKeyStr := base64.StdEncoding.EncodeToString(dataKey.CiphertextBlob)

	return dataKey.Plaintext, encryptedKeyStr, nil
}

// DecryptDEK decrypts an encrypted data encryption key
func (a *KMSKeyProviderAdapter) DecryptDEK(ctx context.Context, encryptedKey string) ([]byte, error) {
	// Decode the base64 string back to bytes
	ciphertextBlob, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	plaintext, err := a.provider.Decrypt(ctx, ciphertextBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}

	return plaintext, nil
}

// Name returns the provider name
func (a *KMSKeyProviderAdapter) Name() string {
	return a.provider.Name()
}
