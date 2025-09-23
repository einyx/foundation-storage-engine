package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// LocalProvider implements Provider interface for local key management
type LocalProvider struct {
	masterKey    []byte
	dataKeyCache *DataKeyCache
}

// NewLocalProvider creates a new local key provider
func NewLocalProvider(ctx context.Context, config map[string]interface{}) (Provider, error) {
	// Get master key from config
	masterKeyStr, ok := config["master_key"].(string)
	if !ok || masterKeyStr == "" {
		return nil, fmt.Errorf("master_key is required for local provider")
	}

	// Try to decode as hex first
	masterKey, err := hex.DecodeString(masterKeyStr)
	if err != nil {
		// If not hex, use raw bytes
		masterKey = []byte(masterKeyStr)
	}

	// Validate key size (must be 16, 24, or 32 bytes for AES)
	keyLen := len(masterKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("master key must be 16, 24, or 32 bytes (got %d)", keyLen)
	}

	// Create data key cache
	cacheTTL := 5 * time.Minute
	if ttl, ok := config["data_key_cache_ttl"].(string); ok {
		if d, err := time.ParseDuration(ttl); err == nil {
			cacheTTL = d
		}
	}

	return &LocalProvider{
		masterKey:    masterKey,
		dataKeyCache: NewDataKeyCache(cacheTTL),
	}, nil
}

// Name returns the provider name
func (p *LocalProvider) Name() string {
	return string(ProviderTypeLocal)
}

// GenerateDataKey generates a new data encryption key
func (p *LocalProvider) GenerateDataKey(ctx context.Context, keyID string, keySpec string) (*ProviderDataKey, error) {
	// Check cache first
	if cachedKey := p.dataKeyCache.Get(keyID); cachedKey != nil {
		return &ProviderDataKey{
			Plaintext:      cachedKey.PlaintextKey,
			CiphertextBlob: cachedKey.CiphertextBlob,
			KeyID:          keyID,
			Provider:       p.Name(),
		}, nil
	}

	// Generate a 256-bit data key by default
	dataKey := make([]byte, 32)
	if keySpec == "AES_128" {
		dataKey = make([]byte, 16)
	}

	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Encrypt the data key with AES-GCM
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data key
	encryptedKey := gcm.Seal(nonce, nonce, dataKey, nil)

	result := &ProviderDataKey{
		Plaintext:      dataKey,
		CiphertextBlob: encryptedKey,
		KeyID:          keyID,
		Provider:       p.Name(),
	}

	// Cache the key
	p.dataKeyCache.Put(keyID, &DataKey{
		PlaintextKey:   dataKey,
		CiphertextBlob: encryptedKey,
		KeyID:          keyID,
		CreatedAt:      time.Now(),
	})

	return result, nil
}

// Decrypt decrypts the encrypted data key
func (p *LocalProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// ValidateKey validates that a key exists and is usable
func (p *LocalProvider) ValidateKey(ctx context.Context, keyID string) error {
	// For local provider, just validate that we can use the master key
	_, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return fmt.Errorf("invalid master key: %w", err)
	}
	return nil
}

// GetKeyInfo retrieves information about a key
func (p *LocalProvider) GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error) {
	return &KeyInfo{
		KeyID:           keyID,
		Enabled:         true,
		Description:     fmt.Sprintf("Local key (master key size: %d bits)", len(p.masterKey)*8),
		SupportsEncrypt: true,
		SupportsDecrypt: true,
		LastValidated:   time.Now(),
	}, nil
}
