// Package stream provides streaming encryption/decryption implementations
package stream

import (
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

const (
	// ChunkSize is the size of each encrypted chunk (4MB)
	ChunkSize = 4 * 1024 * 1024
	// TagSize is the size of the GCM authentication tag
	TagSize = 16
)

// AESGCMEncryptor implements AES-256-GCM encryption
type AESGCMEncryptor struct {
	keyProvider types.KeyProvider
}

// NewAESGCMEncryptor creates a new AES-GCM encryptor
func NewAESGCMEncryptor(keyProvider types.KeyProvider) *AESGCMEncryptor {
	return &AESGCMEncryptor{
		keyProvider: keyProvider,
	}
}

// Encrypt wraps a reader with AES-GCM encryption
func (e *AESGCMEncryptor) Encrypt(ctx context.Context, reader io.Reader, size int64) (io.Reader, map[string]string, error) {
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
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create metadata
	metadata := map[string]string{
		types.MetadataKeyAlgorithm:     string(types.AlgorithmAES256GCM),
		types.MetadataKeyID:            e.keyProvider.Name(),
		types.MetadataKeyEncryptedDEK:  encryptedDEK,
		types.MetadataKeyNonce:         base64.StdEncoding.EncodeToString(nonce),
		types.MetadataKeyEncryptedSize: strconv.FormatInt(size, 10),
	}

	// Create encrypting reader
	encReader := &encryptingReader{
		reader:    reader,
		gcm:       gcm,
		nonce:     nonce,
		chunkSize: ChunkSize,
		buffer:    make([]byte, ChunkSize+TagSize),
	}

	return encReader, metadata, nil
}

// Decrypt wraps a reader with AES-GCM decryption
func (e *AESGCMEncryptor) Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
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

	// Create decrypting reader
	decReader := &decryptingReader{
		reader:    reader,
		gcm:       gcm,
		nonce:     nonce,
		chunkSize: ChunkSize,
		buffer:    make([]byte, ChunkSize+TagSize),
	}

	return decReader, nil
}

// Algorithm returns the encryption algorithm
func (e *AESGCMEncryptor) Algorithm() types.Algorithm {
	return types.AlgorithmAES256GCM
}

// encryptingReader wraps an io.Reader with AES-GCM encryption
type encryptingReader struct {
	reader    io.Reader
	gcm       cipher.AEAD
	nonce     []byte
	chunkSize int
	buffer    []byte
	chunkNum  int
	eof       bool
}

func (r *encryptingReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}

	// Calculate how much we can read based on output buffer size
	// Account for GCM tag overhead
	maxPlaintext := len(p) - TagSize
	if maxPlaintext <= 0 {
		return 0, fmt.Errorf("output buffer too small: need at least %d bytes", TagSize+1)
	}

	// Don't read more than chunk size
	if maxPlaintext > r.chunkSize {
		maxPlaintext = r.chunkSize
	}

	// Read from underlying reader
	n, err := r.reader.Read(r.buffer[:maxPlaintext])
	if err != nil && err != io.EOF {
		return 0, err
	}

	if n == 0 {
		r.eof = true
		return 0, io.EOF
	}

	// Update nonce for this chunk
	chunkNonce := make([]byte, len(r.nonce))
	copy(chunkNonce, r.nonce)
	// XOR chunk number into nonce
	for i := 0; i < 8 && i < len(chunkNonce); i++ {
		chunkNonce[i] ^= byte(r.chunkNum >> (8 * i))
	}
	r.chunkNum++

	// Encrypt chunk
	encrypted := r.gcm.Seal(nil, chunkNonce, r.buffer[:n], nil)

	// Copy to output buffer
	copy(p, encrypted)

	if err == io.EOF {
		r.eof = true
	}

	return len(encrypted), nil
}

// decryptingReader wraps an io.Reader with AES-GCM decryption
type decryptingReader struct {
	reader    io.Reader
	gcm       cipher.AEAD
	nonce     []byte
	chunkSize int
	buffer    []byte
	chunkNum  int
	eof       bool
}

func (r *decryptingReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}

	// Calculate maximum encrypted size we can read based on output buffer
	maxEncrypted := len(p) + TagSize
	if maxEncrypted > r.chunkSize+TagSize {
		maxEncrypted = r.chunkSize + TagSize
	}

	// Read encrypted chunk
	n, err := io.ReadAtLeast(r.reader, r.buffer[:maxEncrypted], TagSize+1)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		if n == 0 {
			r.eof = true
			return 0, io.EOF
		}
		// Process what we got
	} else if err != nil {
		return 0, err
	}

	// Update nonce for this chunk
	chunkNonce := make([]byte, len(r.nonce))
	copy(chunkNonce, r.nonce)
	// XOR chunk number into nonce
	for i := 0; i < 8 && i < len(chunkNonce); i++ {
		chunkNonce[i] ^= byte(r.chunkNum >> (8 * i))
	}
	r.chunkNum++

	// Decrypt chunk
	decrypted, err := r.gcm.Open(nil, chunkNonce, r.buffer[:n], nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt chunk: %w", err)
	}

	// Copy to output buffer
	copy(p, decrypted)

	return len(decrypted), nil
}
