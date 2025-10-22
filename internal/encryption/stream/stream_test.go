package stream

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/encryption/types"
)

// mockKeyProvider implements types.KeyProvider for testing
type mockKeyProvider struct {
	name string
	dek  []byte
}

func newMockKeyProvider() *mockKeyProvider {
	// Generate a 32-byte key for AES-256
	key := make([]byte, 32)
	rand.Read(key)
	
	return &mockKeyProvider{
		name: "test-key",
		dek:  key,
	}
}

func (m *mockKeyProvider) Name() string {
	return m.name
}

func (m *mockKeyProvider) GenerateDEK(ctx context.Context) ([]byte, string, error) {
	// Return the DEK and a mock encrypted version
	encryptedDEK := fmt.Sprintf("encrypted-%x", m.dek)
	return m.dek, encryptedDEK, nil
}

func (m *mockKeyProvider) DecryptDEK(ctx context.Context, encryptedDEK string) ([]byte, error) {
	// For testing, just return the original DEK
	expectedEncrypted := fmt.Sprintf("encrypted-%x", m.dek)
	if encryptedDEK == expectedEncrypted {
		return m.dek, nil
	}
	return nil, fmt.Errorf("invalid encrypted DEK")
}

func TestNewAESGCMEncryptor(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	if encryptor == nil {
		t.Fatal("NewAESGCMEncryptor returned nil")
	}

	if encryptor.keyProvider != keyProvider {
		t.Error("Key provider not set correctly")
	}

	if encryptor.Algorithm() != types.AlgorithmAES256GCM {
		t.Errorf("Expected algorithm %s, got %s", types.AlgorithmAES256GCM, encryptor.Algorithm())
	}
}

func TestNewSimpleAESGCMEncryptor(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)

	if encryptor == nil {
		t.Fatal("NewSimpleAESGCMEncryptor returned nil")
	}

	if encryptor.keyProvider != keyProvider {
		t.Error("Key provider not set correctly")
	}

	if encryptor.maxMemorySize != 100*1024*1024 {
		t.Errorf("Expected maxMemorySize 100MB, got %d", encryptor.maxMemorySize)
	}

	if encryptor.Algorithm() != types.AlgorithmAES256GCM {
		t.Errorf("Expected algorithm %s, got %s", types.AlgorithmAES256GCM, encryptor.Algorithm())
	}
}

func TestReadCloser(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)

	// Test WrapReader with io.Reader
	wrapped := WrapReader(reader)
	if wrapped == nil {
		t.Fatal("WrapReader returned nil")
	}

	// Read data
	result, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if !bytes.Equal(result, data) {
		t.Errorf("Expected %s, got %s", data, result)
	}

	// Test Close
	err = wrapped.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestReadCloser_WithCloser(t *testing.T) {
	// Test WrapReader with io.ReadCloser
	data := []byte("test data")
	reader := io.NopCloser(bytes.NewReader(data))

	wrapped := WrapReader(reader)
	if wrapped != reader {
		t.Error("WrapReader should return original ReadCloser")
	}

	err := wrapped.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestAESGCMEncryptor_Encrypt_SmallData(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	data := []byte("Hello, World!")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	encReader, metadata, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encReader == nil {
		t.Fatal("Encrypted reader is nil")
	}

	if metadata == nil {
		t.Fatal("Metadata is nil")
	}

	// Verify metadata
	if metadata[types.MetadataKeyAlgorithm] != string(types.AlgorithmAES256GCM) {
		t.Errorf("Expected algorithm %s, got %s", types.AlgorithmAES256GCM, metadata[types.MetadataKeyAlgorithm])
	}

	if metadata[types.MetadataKeyID] != keyProvider.Name() {
		t.Errorf("Expected key ID %s, got %s", keyProvider.Name(), metadata[types.MetadataKeyID])
	}

	if metadata[types.MetadataKeyEncryptedDEK] == "" {
		t.Error("Missing encrypted DEK in metadata")
	}

	if metadata[types.MetadataKeyNonce] == "" {
		t.Error("Missing nonce in metadata")
	}

	if metadata[types.MetadataKeyEncryptedSize] == "" {
		t.Error("Missing encrypted size in metadata")
	}

	// Read encrypted data
	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("Encrypted data is empty")
	}

	// Encrypted data should be different from original
	if bytes.Equal(encrypted, data) {
		t.Error("Encrypted data should be different from original")
	}
}

func TestAESGCMEncryptor_EncryptDecrypt_RoundTrip(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	originalData := []byte("This is a test message for encryption and decryption")
	reader := bytes.NewReader(originalData)
	ctx := context.Background()

	// Encrypt
	encReader, metadata, err := encryptor.Encrypt(ctx, reader, int64(len(originalData)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Decrypt
	encryptedReader := bytes.NewReader(encrypted)
	decReader, err := encryptor.Decrypt(ctx, encryptedReader, metadata)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify
	if !bytes.Equal(originalData, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", originalData, decrypted)
	}
}

func TestSimpleAESGCMEncryptor_SmallFile(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)

	originalData := []byte("Small file content for testing")
	reader := bytes.NewReader(originalData)
	ctx := context.Background()

	// Encrypt
	encReader, metadata, err := encryptor.Encrypt(ctx, reader, int64(len(originalData)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Verify metadata
	if metadata[types.MetadataKeyAlgorithm] != string(types.AlgorithmAES256GCM) {
		t.Errorf("Expected algorithm %s, got %s", types.AlgorithmAES256GCM, metadata[types.MetadataKeyAlgorithm])
	}

	// Decrypt
	encryptedReader := bytes.NewReader(encrypted)
	decReader, err := encryptor.Decrypt(ctx, encryptedReader, metadata)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify
	if !bytes.Equal(originalData, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", originalData, decrypted)
	}
}

func TestSimpleAESGCMEncryptor_LargeFile(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)

	// Create a "large" file (larger than memory threshold would be in real usage)
	originalData := make([]byte, 1024*1024) // 1MB
	rand.Read(originalData)

	reader := bytes.NewReader(originalData)
	ctx := context.Background()

	// Encrypt
	encReader, metadata, err := encryptor.Encrypt(ctx, reader, int64(len(originalData)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Decrypt
	encryptedReader := bytes.NewReader(encrypted)
	decReader, err := encryptor.Decrypt(ctx, encryptedReader, metadata)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify
	if !bytes.Equal(originalData, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestAESGCMEncryptor_Decrypt_MissingMetadata(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	data := []byte("test data")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	t.Run("missing_encrypted_dek", func(t *testing.T) {
		metadata := map[string]string{
			types.MetadataKeyNonce: "dGVzdA==",
		}

		_, err := encryptor.Decrypt(ctx, reader, metadata)
		if err == nil {
			t.Error("Expected error for missing encrypted DEK")
		}

		if !strings.Contains(err.Error(), "missing encrypted DEK") {
			t.Errorf("Expected 'missing encrypted DEK' error, got: %v", err)
		}
	})

	t.Run("missing_nonce", func(t *testing.T) {
		metadata := map[string]string{
			types.MetadataKeyEncryptedDEK: "encrypted-key",
		}

		_, err := encryptor.Decrypt(ctx, reader, metadata)
		if err == nil {
			t.Error("Expected error for missing nonce")
		}

		if !strings.Contains(err.Error(), "missing nonce") {
			t.Errorf("Expected 'missing nonce' error, got: %v", err)
		}
	})

	t.Run("invalid_nonce", func(t *testing.T) {
		metadata := map[string]string{
			types.MetadataKeyEncryptedDEK: "encrypted-key",
			types.MetadataKeyNonce:        "invalid-base64!",
		}

		_, err := encryptor.Decrypt(ctx, reader, metadata)
		if err == nil {
			t.Error("Expected error for invalid nonce")
		}

		if !strings.Contains(err.Error(), "failed to decode nonce") {
			t.Errorf("Expected 'failed to decode nonce' error, got: %v", err)
		}
	})
}

func TestSimpleAESGCMEncryptor_Decrypt_MissingMetadata(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)

	data := []byte("test data")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	t.Run("missing_encrypted_dek", func(t *testing.T) {
		metadata := map[string]string{
			types.MetadataKeyNonce: "dGVzdA==",
		}

		_, err := encryptor.Decrypt(ctx, reader, metadata)
		if err == nil {
			t.Error("Expected error for missing encrypted DEK")
		}

		if !strings.Contains(err.Error(), "missing encrypted DEK") {
			t.Errorf("Expected 'missing encrypted DEK' error, got: %v", err)
		}
	})

	t.Run("missing_nonce", func(t *testing.T) {
		metadata := map[string]string{
			types.MetadataKeyEncryptedDEK: "encrypted-key",
		}

		_, err := encryptor.Decrypt(ctx, reader, metadata)
		if err == nil {
			t.Error("Expected error for missing nonce")
		}

		if !strings.Contains(err.Error(), "missing nonce") {
			t.Errorf("Expected 'missing nonce' error, got: %v", err)
		}
	})
}

func TestEncryptingReader_SmallBuffer(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	data := []byte("test")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	encReader, _, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to read with a buffer that's too small
	smallBuffer := make([]byte, TagSize-1)
	_, err = encReader.Read(smallBuffer)
	if err == nil {
		t.Error("Expected error for buffer too small")
	}

	if !strings.Contains(err.Error(), "output buffer too small") {
		t.Errorf("Expected 'output buffer too small' error, got: %v", err)
	}
}

func TestEncryptingReader_MultipleReads(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	// Create data that's smaller but still tests multiple read behavior
	data := []byte("This is a test message that should be long enough to test multiple reads")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	encReader, metadata, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Read encrypted data completely (the streaming reader has limitations)
	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Decrypt and verify
	encryptedReader := bytes.NewReader(encrypted)
	decReader, err := encryptor.Decrypt(ctx, encryptedReader, metadata)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestEncryptingReader_EOF(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	data := []byte("test")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	encReader, _, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Read all data
	buffer := make([]byte, 1024)
	n, err := encReader.Read(buffer)
	if err != nil {
		t.Fatalf("First read failed: %v", err)
	}

	if n == 0 {
		t.Error("First read returned 0 bytes")
	}

	// Try to read again - should get EOF
	_, err = encReader.Read(buffer)
	if err != io.EOF {
		t.Errorf("Expected EOF on second read, got: %v", err)
	}
}

func TestKeyProviderErrors(t *testing.T) {
	// Test with failing key provider
	failingProvider := &failingKeyProvider{}
	encryptor := NewAESGCMEncryptor(failingProvider)

	data := []byte("test")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	_, _, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
	if err == nil {
		t.Error("Expected error from failing key provider")
	}

	if !strings.Contains(err.Error(), "failed to generate DEK") {
		t.Errorf("Expected 'failed to generate DEK' error, got: %v", err)
	}
}

func TestDecryptWithBadDEK(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewAESGCMEncryptor(keyProvider)

	data := []byte("test")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	// Modify metadata to have invalid encrypted DEK
	metadata := map[string]string{
		types.MetadataKeyEncryptedDEK: "invalid-encrypted-dek",
		types.MetadataKeyNonce:        "dGVzdG5vbmNl", // base64 "testnonce"
	}

	_, err := encryptor.Decrypt(ctx, reader, metadata)
	if err == nil {
		t.Error("Expected error for invalid encrypted DEK")
	}

	if !strings.Contains(err.Error(), "failed to decrypt DEK") {
		t.Errorf("Expected 'failed to decrypt DEK' error, got: %v", err)
	}
}

func TestSimpleEncryptorSizeHandling(t *testing.T) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)

	// Test with unknown size (-1)
	data := []byte("test data with unknown size")
	reader := bytes.NewReader(data)
	ctx := context.Background()

	encReader, metadata, err := encryptor.Encrypt(ctx, reader, -1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Should still work
	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("Encrypted data is empty")
	}

	// Verify original size is stored correctly
	if metadata[types.MetadataKeyEncryptedSize] != strconv.FormatInt(-1, 10) {
		t.Errorf("Expected encrypted size -1, got %s", metadata[types.MetadataKeyEncryptedSize])
	}
}

// failingKeyProvider always returns errors
type failingKeyProvider struct{}

func (f *failingKeyProvider) Name() string {
	return "failing-provider"
}

func (f *failingKeyProvider) GenerateDEK(ctx context.Context) ([]byte, string, error) {
	return nil, "", fmt.Errorf("key provider failure")
}

func (f *failingKeyProvider) DecryptDEK(ctx context.Context, encryptedDEK string) ([]byte, error) {
	return nil, fmt.Errorf("key provider failure")
}

func BenchmarkSimpleAESGCMEncrypt_SmallFile(b *testing.B) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)
	data := make([]byte, 1024) // 1KB
	rand.Read(data)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		encReader, _, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
		// Read all encrypted data
		_, err = io.ReadAll(encReader)
		if err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}

func BenchmarkSimpleAESGCMDecrypt_SmallFile(b *testing.B) {
	keyProvider := newMockKeyProvider()
	encryptor := NewSimpleAESGCMEncryptor(keyProvider)
	data := make([]byte, 1024) // 1KB
	rand.Read(data)
	ctx := context.Background()

	// Pre-encrypt data
	reader := bytes.NewReader(data)
	encReader, metadata, err := encryptor.Encrypt(ctx, reader, int64(len(data)))
	if err != nil {
		b.Fatalf("Encrypt failed: %v", err)
	}
	encrypted, err := io.ReadAll(encReader)
	if err != nil {
		b.Fatalf("Read encrypted failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		encryptedReader := bytes.NewReader(encrypted)
		decReader, err := encryptor.Decrypt(ctx, encryptedReader, metadata)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
		// Read all decrypted data
		_, err = io.ReadAll(decReader)
		if err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}

func BenchmarkWrapReader(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		wrapped := WrapReader(reader)
		_, err := io.ReadAll(wrapped)
		if err != nil {
			b.Fatalf("Read failed: %v", err)
		}
		wrapped.Close()
	}
}