package stream

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"

	"github.com/einyx/s3proxy-go/internal/encryption/types"
)

// SimpleAESGCMEncryptor implements AES-256-GCM encryption with a simpler approach
// It encrypts the entire data in memory for objects up to a certain size
type SimpleAESGCMEncryptor struct {
	keyProvider   types.KeyProvider
	maxMemorySize int64 // Maximum size to encrypt in memory (default: 100MB)
}

// NewSimpleAESGCMEncryptor creates a new simple AES-GCM encryptor
func NewSimpleAESGCMEncryptor(keyProvider types.KeyProvider) *SimpleAESGCMEncryptor {
	return &SimpleAESGCMEncryptor{
		keyProvider:   keyProvider,
		maxMemorySize: 100 * 1024 * 1024, // 100MB
	}
}

// Encrypt wraps a reader with AES-GCM encryption
func (e *SimpleAESGCMEncryptor) Encrypt(ctx context.Context, reader io.Reader, size int64) (io.Reader, map[string]string, error) {
	// Generate a new DEK
	dek, encryptedDEK, err := e.keyProvider.GenerateDEK(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, randErr := rand.Read(nonce); randErr != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", randErr)
	}

	// For small files, encrypt in memory
	if size >= 0 && size <= e.maxMemorySize {
		// Read all data
		data, readErr := io.ReadAll(reader)
		if readErr != nil {
			return nil, nil, fmt.Errorf("failed to read data: %w", readErr)
		}

		// Encrypt data (nonce is stored separately in metadata)
		encrypted := gcm.Seal(nil, nonce, data, nil)

		// Create metadata
		metadata := map[string]string{
			types.MetadataKeyAlgorithm:     string(types.AlgorithmAES256GCM),
			types.MetadataKeyID:            e.keyProvider.Name(),
			types.MetadataKeyEncryptedDEK:  encryptedDEK,
			types.MetadataKeyNonce:         base64.StdEncoding.EncodeToString(nonce),
			types.MetadataKeyEncryptedSize: strconv.FormatInt(int64(len(data)), 10),
		}

		return bytes.NewReader(encrypted), metadata, nil
	}

	// For large files, use streaming encryption
	// Create metadata
	metadata := map[string]string{
		types.MetadataKeyAlgorithm:     string(types.AlgorithmAES256GCM),
		types.MetadataKeyID:            e.keyProvider.Name(),
		types.MetadataKeyEncryptedDEK:  encryptedDEK,
		types.MetadataKeyNonce:         base64.StdEncoding.EncodeToString(nonce),
		types.MetadataKeyEncryptedSize: strconv.FormatInt(size, 10),
	}

	// For now, fall back to in-memory encryption for large files too
	// TODO: Implement proper streaming encryption with chunking
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Encrypt data (nonce is stored separately in metadata)
	encrypted := gcm.Seal(nil, nonce, data, nil)

	return bytes.NewReader(encrypted), metadata, nil
}

// Decrypt wraps a reader with AES-GCM decryption
func (e *SimpleAESGCMEncryptor) Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
	// Extract encryption metadata
	encryptedDEK := metadata[types.MetadataKeyEncryptedDEK]
	if encryptedDEK == "" {
		return nil, fmt.Errorf("missing encrypted DEK in metadata")
	}

	nonceStr := metadata[types.MetadataKeyNonce]
	if nonceStr == "" {
		return nil, fmt.Errorf("missing nonce in metadata")
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Get original size if available
	var originalSize int64 = -1
	if sizeStr := metadata[types.MetadataKeyEncryptedSize]; sizeStr != "" {
		if parsedSize, parseErr := strconv.ParseInt(sizeStr, 10, 64); parseErr == nil {
			originalSize = parsedSize
		}
	}

	// Decrypt DEK
	dek, err := e.keyProvider.DecryptDEK(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// For small files, decrypt in memory
	if originalSize >= 0 && originalSize <= e.maxMemorySize {
		// Read all encrypted data
		encrypted, readErr := io.ReadAll(reader)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read encrypted data: %w", readErr)
		}

		// Nonce is stored in metadata, encrypted data doesn't include nonce
		// Decrypt data directly
		decrypted, decryptErr := gcm.Open(nil, nonce, encrypted, nil)
		if decryptErr != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", decryptErr)
		}

		return bytes.NewReader(decrypted), nil
	}

	// For large files, use streaming decryption
	// For now, fall back to in-memory decryption for large files too
	// TODO: Implement proper streaming decryption with chunking
	encrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Nonce is stored in metadata, encrypted data doesn't include nonce
	decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return bytes.NewReader(decrypted), nil
}

// Algorithm returns the encryption algorithm
func (e *SimpleAESGCMEncryptor) Algorithm() types.Algorithm {
	return types.AlgorithmAES256GCM
}

// TODO: Implement proper streaming encryption for very large files
// For now, we fall back to in-memory encryption for all files
//
// A proper streaming implementation would:
// 1. Use chunk-based encryption with separate nonces per chunk
// 2. Include chunk headers with sequence numbers for integrity
// 3. Support parallel processing of chunks
// 4. Handle partial reads/writes correctly
