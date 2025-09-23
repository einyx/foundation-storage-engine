package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

// CustomProvider implements Provider interface for custom encryption keys
type CustomProvider struct {
	masterKey         []byte
	keyDerivationSalt []byte
	dataKeyCache      *DataKeyCache
}

// NewCustomProvider creates a new custom key provider
func NewCustomProvider(ctx context.Context, config map[string]interface{}) (Provider, error) {
	// Get master key from config
	var masterKey []byte

	if mkStr, ok := config["master_key"].(string); ok && mkStr != "" {
		// Try base64 decoding first
		if decoded, err := base64.StdEncoding.DecodeString(mkStr); err == nil {
			masterKey = decoded
		} else {
			// Use as raw string if not base64
			masterKey = []byte(mkStr)
		}
	} else if mkFile, ok := config["master_key_file"].(string); ok && mkFile != "" {
		// Read from file
		// In production, you'd read from the file
		return nil, fmt.Errorf("master_key_file not implemented yet")
	} else {
		return nil, fmt.Errorf("master_key or master_key_file is required for custom provider")
	}

	// Validate key size
	keyLen := len(masterKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		// If not a valid AES key size, derive a key from it
		hash := sha256.Sum256(masterKey)
		masterKey = hash[:]
	}

	// Get or generate key derivation salt
	var salt []byte
	if saltStr, ok := config["key_derivation_salt"].(string); ok {
		salt, _ = base64.StdEncoding.DecodeString(saltStr)
	}
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Create data key cache
	cacheTTL := 5 * time.Minute
	if ttl, ok := config["data_key_cache_ttl"].(string); ok {
		if d, err := time.ParseDuration(ttl); err == nil {
			cacheTTL = d
		}
	}

	return &CustomProvider{
		masterKey:         masterKey,
		keyDerivationSalt: salt,
		dataKeyCache:      NewDataKeyCache(cacheTTL),
	}, nil
}

// Name returns the provider name
func (p *CustomProvider) Name() string {
	return string(ProviderTypeCustom)
}

// GenerateDataKey generates a new data encryption key
func (p *CustomProvider) GenerateDataKey(ctx context.Context, keyID string, keySpec string) (*ProviderDataKey, error) {
	// Check cache first
	if cachedKey := p.dataKeyCache.Get(keyID); cachedKey != nil {
		return &ProviderDataKey{
			Plaintext:      cachedKey.PlaintextKey,
			CiphertextBlob: cachedKey.CiphertextBlob,
			KeyID:          keyID,
			Provider:       p.Name(),
		}, nil
	}

	// Determine key size
	keySize := 32 // Default to 256 bits
	if keySpec == "AES_128" {
		keySize = 16
	} else if keySpec == "AES_192" {
		keySize = 24
	}

	// Generate random data key
	plaintext := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Encrypt data key with master key
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Use GCM mode for authenticated encryption
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with keyID as additional data
	ciphertext := aead.Seal(nonce, nonce, plaintext, []byte(keyID))

	dataKey := &ProviderDataKey{
		Plaintext:      plaintext,
		CiphertextBlob: ciphertext,
		KeyID:          keyID,
		Provider:       p.Name(),
	}

	// Cache the key
	p.dataKeyCache.Put(keyID, &DataKey{
		PlaintextKey:   plaintext,
		CiphertextBlob: ciphertext,
		KeyID:          keyID,
		CreatedAt:      time.Now(),
	})

	return dataKey, nil
}

// Decrypt decrypts the encrypted data key
func (p *CustomProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	// Decrypt (we don't have the keyID here, so we can't verify additional data)
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// ValidateKey validates that a key exists and is usable
func (p *CustomProvider) ValidateKey(ctx context.Context, keyID string) error {
	// For custom provider, we just check that we have a valid master key
	if len(p.masterKey) == 0 {
		return fmt.Errorf("master key not configured")
	}

	// Try to create a cipher to validate the key
	_, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return fmt.Errorf("invalid master key: %w", err)
	}

	return nil
}

// GetKeyInfo retrieves information about a key
func (p *CustomProvider) GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error) {
	// Validate the master key
	if err := p.ValidateKey(ctx, keyID); err != nil {
		return nil, err
	}

	return &KeyInfo{
		KeyID:           keyID,
		Enabled:         true,
		Description:     fmt.Sprintf("Custom key (size: %d bits)", len(p.masterKey)*8),
		SupportsEncrypt: true,
		SupportsDecrypt: true,
		LastValidated:   time.Now(),
	}, nil
}
