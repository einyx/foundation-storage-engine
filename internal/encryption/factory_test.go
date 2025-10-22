package encryption

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

func makeBase64Key(t *testing.T) string {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	return base64.StdEncoding.EncodeToString(key)
}

func TestNewFromConfig_LocalProvider(t *testing.T) {
	t.Parallel()

	cfg := &config.EncryptionConfig{
		Enabled:     true,
		Algorithm:   "AES-256-GCM",
		KeyProvider: "local",
		Local: &config.LocalKeyConfig{
			MasterKey: makeBase64Key(t),
		},
	}

	manager, err := NewFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected local provider to initialise, got error: %v", err)
	}

	if manager == nil || !manager.IsEnabled() {
		t.Fatalf("expected enabled manager, got %#v", manager)
	}
}

func TestNewFromConfig_LocalProviderInvalidKey(t *testing.T) {
	t.Parallel()

	cfg := &config.EncryptionConfig{
		Enabled:     true,
		Algorithm:   "AES-256-GCM",
		KeyProvider: "local",
		Local: &config.LocalKeyConfig{
			MasterKey: "not-base64",
		},
	}

	if _, err := NewFromConfig(context.Background(), cfg); err == nil {
		t.Fatal("expected error for invalid base64 master key, got nil")
	}
}

func TestNewFromConfig_Disabled(t *testing.T) {
	t.Parallel()

	manager, err := NewFromConfig(context.Background(), &config.EncryptionConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected disabled manager without error, got: %v", err)
	}

	if manager == nil {
		t.Fatal("expected manager instance when disabled")
	}

	if manager.IsEnabled() {
		t.Fatal("expected manager to be disabled")
	}
}

func TestNewFromConfig_InvalidProvider(t *testing.T) {
	t.Parallel()

	cfg := &config.EncryptionConfig{
		Enabled:     true,
		KeyProvider: "unsupported",
	}

	if _, err := NewFromConfig(context.Background(), cfg); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestNewFromConfig_NamedLocalProvider(t *testing.T) {
	t.Parallel()

	cfg := &config.EncryptionConfig{
		Enabled:     true,
		Algorithm:   "AES-256-GCM",
		KeyProvider: "primary",
		KeyProviders: map[string]config.ProviderConfig{
			"primary": {
				Type: "local",
				Config: map[string]interface{}{
					"master_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				},
			},
		},
	}

	manager, err := NewFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected manager for named local provider, got error: %v", err)
	}

	if manager == nil || !manager.IsEnabled() {
		t.Fatalf("expected enabled manager, got %#v", manager)
	}
}
