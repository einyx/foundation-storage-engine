// Package keys provides key management implementations for encryption.
package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// LocalKeyProvider provides local key management for development/testing
type LocalKeyProvider struct {
	masterKey []byte
}

// NewLocalKeyProvider creates a new local key provider with a master key
func NewLocalKeyProvider(masterKey []byte) (*LocalKeyProvider, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (256 bits)")
	}

	return &LocalKeyProvider{
		masterKey: masterKey,
	}, nil
}

// GenerateDEK generates a new data encryption key
func (p *LocalKeyProvider) GenerateDEK(ctx context.Context) ([]byte, string, error) {
	// Generate a random 256-bit DEK
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, "", fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt the DEK with the master key using AES-GCM
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt DEK
	encryptedDEK := gcm.Seal(nonce, nonce, dek, nil)

	// Encode as base64 for storage
	encodedDEK := base64.StdEncoding.EncodeToString(encryptedDEK)

	return dek, encodedDEK, nil
}

// DecryptDEK decrypts an encrypted data encryption key
func (p *LocalKeyProvider) DecryptDEK(ctx context.Context, encryptedKey string) ([]byte, error) {
	// Decode from base64
	encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(encryptedDEK) < nonceSize {
		return nil, fmt.Errorf("encrypted DEK too short")
	}

	nonce, ciphertext := encryptedDEK[:nonceSize], encryptedDEK[nonceSize:]

	// Decrypt DEK
	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return dek, nil
}

// Name returns the provider name
func (p *LocalKeyProvider) Name() string {
	return "local"
}
