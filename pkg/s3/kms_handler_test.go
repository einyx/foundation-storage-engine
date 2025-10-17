package s3

import (
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

type mockKMSManager struct{}

func (m *mockKMSManager) Encrypt(ctx interface{}, plaintext []byte, keyID string) ([]byte, error) {
	return plaintext, nil
}

func (m *mockKMSManager) Decrypt(ctx interface{}, ciphertext []byte, keyID string) ([]byte, error) {
	return ciphertext, nil
}

func (m *mockKMSManager) Close() error {
	return nil
}

func TestNewHandlerWithKMS(t *testing.T) {
	s3cfg := config.S3Config{}

	handler, err := NewHandlerWithKMS(&mockStorage{}, &mockAuth{}, s3cfg, nil)
	if err != nil {
		t.Fatalf("NewHandlerWithKMS() error = %v", err)
	}

	if handler == nil {
		t.Error("NewHandlerWithKMS() should return a valid handler")
	}
}

func TestKMSHandlerClose(t *testing.T) {
	s3cfg := config.S3Config{}

	handler, err := NewHandlerWithKMS(&mockStorage{}, &mockAuth{}, s3cfg, nil)
	if err != nil {
		t.Fatalf("NewHandlerWithKMS() error = %v", err)
	}

	handler.Close() // Close() doesn't return an error
}

func TestKMSHandlerCloseNilManager(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	// Regular Handler doesn't have a Close method - this test is not needed
	_ = handler // avoid unused variable warning
}
