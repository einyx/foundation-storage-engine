package kms

import (
	"context"
	"fmt"
)

// Provider defines the interface for key management providers
type Provider interface {
	// Name returns the provider name
	Name() string

	// GenerateDataKey generates a new data encryption key
	GenerateDataKey(ctx context.Context, keyID string, keySpec string) (*ProviderDataKey, error)

	// Decrypt decrypts the encrypted data key
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)

	// ValidateKey validates that a key exists and is usable
	ValidateKey(ctx context.Context, keyID string) error

	// GetKeyInfo retrieves information about a key
	GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error)
}

// ProviderDataKey represents a data encryption key from a provider
type ProviderDataKey struct {
	// Plaintext is the decrypted data key
	Plaintext []byte

	// CiphertextBlob is the encrypted data key
	CiphertextBlob []byte

	// KeyID is the ID of the key used to encrypt this data key
	KeyID string

	// Provider is the name of the provider that generated this key
	Provider string
}

// ProviderType represents the type of key provider
type ProviderType string

const (
	ProviderTypeAWSKMS  ProviderType = "aws-kms"
	ProviderTypeAzureKV ProviderType = "azure-keyvault"
	ProviderTypeCustom  ProviderType = "custom"
	ProviderTypeLocal   ProviderType = "local"
)

// ProviderConfig holds configuration for a specific provider
type ProviderConfig struct {
	Type   ProviderType           `yaml:"type" json:"type"`
	Config map[string]interface{} `yaml:"config" json:"config"`
}

// NewProvider creates a new provider based on the configuration
func NewProvider(ctx context.Context, cfg *ProviderConfig) (Provider, error) {
	switch cfg.Type {
	case ProviderTypeAWSKMS:
		return NewAWSKMSProvider(ctx, cfg.Config)
	case ProviderTypeAzureKV:
		return NewAzureKeyVaultProvider(ctx, cfg.Config)
	case ProviderTypeCustom:
		return NewCustomProvider(ctx, cfg.Config)
	case ProviderTypeLocal:
		return NewLocalProvider(ctx, cfg.Config)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", cfg.Type)
	}
}
