package kms

import (
	"context"
	"fmt"
	"time"
)

// AzureKeyVaultProvider implements Provider interface for Azure Key Vault (stub implementation)
type AzureKeyVaultProvider struct {
	// vaultURL     string        // TODO: Uncomment when implementing Azure Key Vault integration
	// dataKeyCache *DataKeyCache // TODO: Uncomment when implementing Azure Key Vault integration
	// keySize      int32         // TODO: Uncomment when implementing Azure Key Vault integration
}

// NewAzureKeyVaultProvider creates a new Azure Key Vault provider
func NewAzureKeyVaultProvider(ctx context.Context, config map[string]interface{}) (Provider, error) {
	// TODO: Implement full Azure Key Vault integration
	return nil, fmt.Errorf("azure Key Vault provider not yet fully implemented - use local or aws-kms for now")
}

// Name returns the provider name
func (p *AzureKeyVaultProvider) Name() string {
	return string(ProviderTypeAzureKV)
}

// GenerateDataKey generates a new data encryption key
func (p *AzureKeyVaultProvider) GenerateDataKey(ctx context.Context, keyID string, keySpec string) (*ProviderDataKey, error) {
	return nil, fmt.Errorf("azure Key Vault provider not yet implemented")
}

// Decrypt decrypts the encrypted data key
func (p *AzureKeyVaultProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("azure Key Vault provider not yet implemented")
}

// ValidateKey validates that a key exists and is usable
func (p *AzureKeyVaultProvider) ValidateKey(ctx context.Context, keyID string) error {
	return fmt.Errorf("azure Key Vault provider not yet implemented")
}

// GetKeyInfo retrieves information about a key
func (p *AzureKeyVaultProvider) GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error) {
	return &KeyInfo{
		KeyID:         keyID,
		Enabled:       false,
		Description:   "Azure Key Vault provider (not implemented)",
		LastValidated: time.Now(),
	}, nil
}
