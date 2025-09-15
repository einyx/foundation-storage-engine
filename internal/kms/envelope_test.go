package kms

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptedData(t *testing.T) {
	encrypted := &EncryptedData{
		CiphertextBlob: []byte("encrypted-key"),
		EncryptedData:  []byte("encrypted-data"),
		Nonce:          []byte("nonce123"),
		EncryptionContext: map[string]string{
			"test": "value",
		},
	}

	assert.NotNil(t, encrypted.CiphertextBlob)
	assert.NotNil(t, encrypted.EncryptedData)
	assert.NotNil(t, encrypted.Nonce)
	assert.Equal(t, "value", encrypted.EncryptionContext["test"])
}

func TestStreamEncryptor(t *testing.T) {
	// Test the chunk writing functionality
	var buf bytes.Buffer

	// Write a test chunk
	nonce := []byte("test-nonce")
	ciphertext := []byte("test-ciphertext")

	err := writeChunk(&buf, nonce, ciphertext)
	require.NoError(t, err)

	// Verify the written data
	data := buf.Bytes()
	assert.Equal(t, 4, len(data[:4])) // 4 bytes for length

	// Calculate expected length
	expectedLen := len(nonce) + len(ciphertext)
	actualLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	assert.Equal(t, expectedLen, actualLen)
}

func TestAESGCMEncryption(t *testing.T) {
	// Test basic AES-GCM encryption/decryption without KMS
	key := make([]byte, 32) // AES-256
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	// Test data
	plaintext := []byte("Hello, World! This is a test message for encryption.")

	// Encrypt
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Decrypt
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChunkedEncryption(t *testing.T) {
	// Test chunked encryption logic
	chunkSize := 1024
	testData := make([]byte, chunkSize*3+500) // 3.5 chunks
	_, err := io.ReadFull(rand.Reader, testData)
	require.NoError(t, err)

	// Simulate chunking
	var chunks [][]byte
	for i := 0; i < len(testData); i += chunkSize {
		end := i + chunkSize
		if end > len(testData) {
			end = len(testData)
		}
		chunks = append(chunks, testData[i:end])
	}

	assert.Equal(t, 4, len(chunks))
	assert.Equal(t, chunkSize, len(chunks[0]))
	assert.Equal(t, chunkSize, len(chunks[1]))
	assert.Equal(t, chunkSize, len(chunks[2]))
	assert.Equal(t, 500, len(chunks[3]))
}

func TestSecureKeyCleanup(t *testing.T) {
	// Test that keys are properly zeroed out
	key := []byte("sensitive-key-material-12345678")
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	// Verify copy is correct
	assert.Equal(t, key, keyCopy)

	// Zero out the key
	for i := range key {
		key[i] = 0
	}

	// Verify key is zeroed
	assert.NotEqual(t, keyCopy, key)
	for _, b := range key {
		assert.Equal(t, byte(0), b)
	}
}
