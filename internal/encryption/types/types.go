// Package types defines common types and interfaces for encryption
package types

import (
	"context"
	"io"
)

// Algorithm represents the encryption algorithm to use
type Algorithm string

// Supported encryption algorithms
const (
	AlgorithmAES256GCM        Algorithm = "AES-256-GCM"
	AlgorithmChaCha20Poly1305 Algorithm = "ChaCha20-Poly1305"
)

// KeyProvider defines the interface for encryption key management
type KeyProvider interface {
	// GenerateDEK generates a new data encryption key
	GenerateDEK(ctx context.Context) (key []byte, encryptedKey string, err error)

	// DecryptDEK decrypts an encrypted data encryption key
	DecryptDEK(ctx context.Context, encryptedKey string) (key []byte, err error)

	// Name returns the provider name for identification
	Name() string
}

// Encryptor defines the interface for encrypting and decrypting data
type Encryptor interface {
	// Encrypt wraps a reader with encryption
	Encrypt(ctx context.Context, reader io.Reader, size int64) (encrypted io.Reader, metadata map[string]string, err error)

	// Decrypt wraps a reader with decryption
	Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (decrypted io.Reader, err error)

	// Algorithm returns the encryption algorithm used
	Algorithm() Algorithm
}

// EncryptionMetadata stores encryption-related information
type EncryptionMetadata struct {
	Algorithm     Algorithm `json:"algorithm"`
	KeyID         string    `json:"key_id"`
	EncryptedDEK  string    `json:"encrypted_dek"`
	Nonce         string    `json:"nonce"`
	EncryptedSize int64     `json:"encrypted_size"`
}

// MetadataKeys defines the keys used in object metadata
const (
	MetadataKeyAlgorithm     = "x-amz-meta-encryption-algorithm"
	MetadataKeyID            = "x-amz-meta-encryption-key-id"
	MetadataKeyEncryptedDEK  = "x-amz-meta-encryption-dek"
	MetadataKeyNonce         = "x-amz-meta-encryption-nonce"
	MetadataKeyEncryptedSize = "x-amz-meta-encrypted-size"
)
