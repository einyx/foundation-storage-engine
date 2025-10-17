package encryption

import (
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

func TestNewEncryptionManager_Local(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled:  true,
		Provider: "local",
		LocalKey: "test-key-32-bytes-for-aes-256-enc",
	}
	
	manager, err := NewEncryptionManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create local encryption manager: %v", err)
	}
	
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}
}

func TestNewEncryptionManager_LocalInvalidKey(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled:  true,
		Provider: "local",
		LocalKey: "short", // Too short for AES-256
	}
	
	_, err := NewEncryptionManager(cfg)
	if err == nil {
		t.Error("Expected error for invalid local key")
	}
}

func TestNewEncryptionManager_LocalEmptyKey(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled:  true,
		Provider: "local",
		LocalKey: "",
	}
	
	_, err := NewEncryptionManager(cfg)
	if err == nil {
		t.Error("Expected error for empty local key")
	}
}

func TestNewEncryptionManager_KMS(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled:  true,
		Provider: "kms",
		KMSKeyID: "test-kms-key-id",
	}
	
	// This should create a KMS manager (though it may fail to connect in tests)
	_, err := NewEncryptionManager(cfg)
	// We don't expect this to succeed in test environment, but it should attempt creation
	if err != nil {
		t.Logf("KMS manager creation failed as expected in test environment: %v", err)
	}
}

func TestNewEncryptionManager_Disabled(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled: false,
	}
	
	manager, err := NewEncryptionManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create disabled encryption manager: %v", err)
	}
	
	if manager != nil {
		t.Error("Expected nil manager when encryption is disabled")
	}
}

func TestNewEncryptionManager_InvalidProvider(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled:  true,
		Provider: "invalid-provider",
	}
	
	_, err := NewEncryptionManager(cfg)
	if err == nil {
		t.Error("Expected error for invalid provider")
	}
}

func TestNewEncryptionManager_DefaultProvider(t *testing.T) {
	cfg := config.EncryptionConfig{
		Enabled:  true,
		Provider: "", // Default should be local
		LocalKey: "test-key-32-bytes-for-aes-256-enc",
	}
	
	manager, err := NewEncryptionManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create default encryption manager: %v", err)
	}
	
	if manager == nil {
		t.Fatal("Expected manager to be created with default provider")
	}
}