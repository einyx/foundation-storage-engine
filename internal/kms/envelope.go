package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EnvelopeEncryptor handles envelope encryption using KMS data keys
type EnvelopeEncryptor struct {
	manager *Manager
}

// NewEnvelopeEncryptor creates a new envelope encryptor
func NewEnvelopeEncryptor(manager *Manager) *EnvelopeEncryptor {
	if manager == nil {
		return nil
	}
	return &EnvelopeEncryptor{
		manager: manager,
	}
}

// EncryptedData represents encrypted data with its metadata
type EncryptedData struct {
	CiphertextBlob    []byte            // Encrypted data key
	EncryptedData     []byte            // Encrypted content
	Nonce             []byte            // GCM nonce
	EncryptionContext map[string]string // KMS encryption context
}

// Encrypt performs envelope encryption on data
func (e *EnvelopeEncryptor) Encrypt(plaintext []byte, keyID string, encContext map[string]string) (*EncryptedData, error) {
	if e == nil || e.manager == nil {
		return nil, fmt.Errorf("envelope encryptor not initialized")
	}

	if !e.manager.IsEnabled() {
		return nil, ErrKMSNotEnabled
	}

	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	// Generate a data key from KMS
	dataKey, err := e.manager.GenerateDataKey(context.TODO(), keyID, encContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Ensure we clean up the key on any error
	defer func() {
		if dataKey != nil && dataKey.PlaintextKey != nil {
			for i := range dataKey.PlaintextKey {
				dataKey.PlaintextKey[i] = 0
			}
		}
	}()

	// Use AES-GCM for encrypting the actual data
	block, err := aes.NewCipher(dataKey.PlaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedData{
		CiphertextBlob:    dataKey.CiphertextBlob,
		EncryptedData:     ciphertext,
		Nonce:             nonce,
		EncryptionContext: encContext,
	}, nil
}

// Decrypt performs envelope decryption on data
func (e *EnvelopeEncryptor) Decrypt(encrypted *EncryptedData) ([]byte, error) {
	if e == nil || e.manager == nil {
		return nil, fmt.Errorf("envelope encryptor not initialized")
	}

	if !e.manager.IsEnabled() {
		return nil, ErrKMSNotEnabled
	}

	if encrypted == nil {
		return nil, fmt.Errorf("encrypted data cannot be nil")
	}

	if len(encrypted.CiphertextBlob) == 0 || len(encrypted.EncryptedData) == 0 || len(encrypted.Nonce) == 0 {
		return nil, fmt.Errorf("invalid encrypted data: missing required fields")
	}

	// Decrypt the data key using KMS
	dataKey, err := e.manager.DecryptDataKey(context.TODO(), encrypted.CiphertextBlob, encrypted.EncryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}

	// Ensure we clean up the key on any error
	defer func() {
		if dataKey != nil && dataKey.PlaintextKey != nil {
			for i := range dataKey.PlaintextKey {
				dataKey.PlaintextKey[i] = 0
			}
		}
	}()

	// Use AES-GCM for decrypting the actual data
	block, err := aes.NewCipher(dataKey.PlaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Validate nonce size
	if len(encrypted.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", gcm.NonceSize(), len(encrypted.Nonce))
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, encrypted.Nonce, encrypted.EncryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// StreamEncryptor provides streaming encryption using KMS
type StreamEncryptor struct {
	writer    io.Writer
	dataKey   *DataKey
	gcm       cipher.AEAD
	chunkSize int
	buffer    []byte
}

// NewStreamEncryptor creates a new streaming encryptor
func (e *EnvelopeEncryptor) NewStreamEncryptor(w io.Writer, keyID string, encContext map[string]string) (*StreamEncryptor, error) {
	if e == nil || e.manager == nil {
		return nil, fmt.Errorf("envelope encryptor not initialized")
	}

	if !e.manager.IsEnabled() {
		return nil, ErrKMSNotEnabled
	}

	if w == nil {
		return nil, fmt.Errorf("writer cannot be nil")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	// Generate a data key from KMS
	dataKey, err := e.manager.GenerateDataKey(context.TODO(), keyID, encContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(dataKey.PlaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &StreamEncryptor{
		writer:    w,
		dataKey:   dataKey,
		gcm:       gcm,
		chunkSize: 64 * 1024, // 64KB chunks
		buffer:    make([]byte, 0, 64*1024),
	}, nil
}

// Write implements io.Writer for streaming encryption
func (s *StreamEncryptor) Write(p []byte) (n int, err error) {
	if s == nil {
		return 0, fmt.Errorf("stream encryptor not initialized")
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Buffer data until we have a full chunk
	s.buffer = append(s.buffer, p...)
	n = len(p)

	// Process full chunks
	for len(s.buffer) >= s.chunkSize {
		if err := s.encryptChunk(s.buffer[:s.chunkSize]); err != nil {
			return n, err
		}
		s.buffer = s.buffer[s.chunkSize:]
	}

	return n, nil
}

// Close flushes remaining data and cleans up
func (s *StreamEncryptor) Close() error {
	if s == nil {
		return nil
	}

	// Encrypt any remaining data
	if len(s.buffer) > 0 {
		if err := s.encryptChunk(s.buffer); err != nil {
			return err
		}
		s.buffer = nil // Clear buffer reference
	}

	// Zero out the plaintext key
	if s.dataKey != nil && s.dataKey.PlaintextKey != nil {
		for i := range s.dataKey.PlaintextKey {
			s.dataKey.PlaintextKey[i] = 0
		}
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// encryptChunk encrypts a single chunk of data
func (s *StreamEncryptor) encryptChunk(chunk []byte) error {
	if s == nil || s.gcm == nil {
		return fmt.Errorf("stream encryptor not properly initialized")
	}

	if len(chunk) == 0 {
		return nil
	}

	// Generate a random nonce for this chunk
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the chunk
	ciphertext := s.gcm.Seal(nil, nonce, chunk, nil)

	// Write nonce length, nonce, and ciphertext
	if err := writeChunk(s.writer, nonce, ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted chunk: %w", err)
	}

	return nil
}

// writeChunk writes an encrypted chunk with its metadata
func writeChunk(w io.Writer, nonce, ciphertext []byte) error {
	if w == nil {
		return fmt.Errorf("writer cannot be nil")
	}

	// Validate chunk size to prevent integer overflow
	chunkLen := len(nonce) + len(ciphertext)
	if chunkLen > 16*1024*1024 { // 16MB max chunk size
		return fmt.Errorf("chunk size too large: %d bytes", chunkLen)
	}

	// Write chunk header: [4 bytes chunk length][nonce][ciphertext]
	header := []byte{
		byte(chunkLen >> 24),
		byte(chunkLen >> 16),
		byte(chunkLen >> 8),
		byte(chunkLen),
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}

	return nil
}
