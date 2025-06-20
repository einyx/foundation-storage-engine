package encryption

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/einyx/s3proxy-go/internal/config"
	"github.com/einyx/s3proxy-go/internal/encryption/keys"
	"github.com/einyx/s3proxy-go/internal/encryption/stream"
	"github.com/einyx/s3proxy-go/internal/encryption/types"
	"github.com/einyx/s3proxy-go/internal/kms"
)

// NewFromConfig creates an encryption manager from configuration
func NewFromConfig(ctx context.Context, cfg *config.EncryptionConfig) (*Manager, error) {
	if !cfg.Enabled {
		return &Manager{enabled: false}, nil
	}

	// Create key provider
	keyProvider, err := createKeyProvider(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	// Create encryptor
	encryptor, err := createEncryptor(cfg, keyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return NewManager(keyProvider, encryptor, true), nil
}

// createKMSProvider creates a KMS provider from a provider config
func createKMSProvider(ctx context.Context, cfg *config.ProviderConfig) (types.KeyProvider, error) {
	// Convert KMS provider to encryption key provider adapter
	kmsProvider, err := kms.NewProvider(ctx, &kms.ProviderConfig{
		Type:   kms.ProviderType(cfg.Type),
		Config: cfg.Config,
	})
	if err != nil {
		return nil, err
	}

	// Create adapter to convert KMS provider to encryption key provider
	return NewKMSKeyProviderAdapter(kmsProvider), nil
}

func createKeyProvider(ctx context.Context, cfg *config.EncryptionConfig) (types.KeyProvider, error) {
	// Check if we have a named provider first
	if providerName := cfg.KeyProvider; providerName != "" {
		if namedProvider, ok := cfg.KeyProviders[providerName]; ok {
			return createKMSProvider(ctx, &namedProvider)
		}
	}

	// Fall back to legacy configuration
	switch cfg.KeyProvider {
	case "local":
		if cfg.Local == nil || cfg.Local.MasterKey == "" {
			return nil, fmt.Errorf("local key provider requires master key")
		}

		// Decode base64 master key
		masterKey, err := base64.StdEncoding.DecodeString(cfg.Local.MasterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode master key: %w", err)
		}

		return keys.NewLocalKeyProvider(masterKey)

	case "kms", "aws-kms":
		if cfg.KMS == nil || cfg.KMS.DefaultKeyID == "" {
			return nil, fmt.Errorf("KMS key provider requires key ID")
		}

		providerCfg := &config.ProviderConfig{
			Type: "aws-kms",
			Config: map[string]interface{}{
				"default_key_id":     cfg.KMS.DefaultKeyID,
				"region":             cfg.KMS.Region,
				"encryption_context": cfg.KMS.EncryptionContext,
				"data_key_cache_ttl": cfg.KMS.DataKeyCacheTTL,
				"key_spec":           cfg.KMS.KeySpec,
			},
		}
		return createKMSProvider(ctx, providerCfg)

	case "azure-keyvault", "azure-kv":
		if cfg.AzureKV == nil || cfg.AzureKV.VaultURL == "" {
			return nil, fmt.Errorf("azure Key Vault provider requires vault URL")
		}

		providerCfg := &config.ProviderConfig{
			Type: "azure-keyvault",
			Config: map[string]interface{}{
				"vault_url":          cfg.AzureKV.VaultURL,
				"client_id":          cfg.AzureKV.ClientID,
				"client_secret":      cfg.AzureKV.ClientSecret,
				"tenant_id":          cfg.AzureKV.TenantID,
				"key_size":           cfg.AzureKV.KeySize,
				"data_key_cache_ttl": cfg.AzureKV.DataKeyCacheTTL,
			},
		}
		return createKMSProvider(ctx, providerCfg)

	case "custom":
		if cfg.Custom == nil || (cfg.Custom.MasterKey == "" && cfg.Custom.MasterKeyFile == "") {
			return nil, fmt.Errorf("custom key provider requires master key or master key file")
		}

		providerCfg := &config.ProviderConfig{
			Type: "custom",
			Config: map[string]interface{}{
				"master_key":          cfg.Custom.MasterKey,
				"master_key_file":     cfg.Custom.MasterKeyFile,
				"key_derivation_salt": cfg.Custom.KeyDerivationSalt,
				"data_key_cache_ttl":  cfg.Custom.DataKeyCacheTTL,
			},
		}
		return createKMSProvider(ctx, providerCfg)

	default:
		return nil, fmt.Errorf("unsupported key provider: %s", cfg.KeyProvider)
	}
}

func createEncryptor(cfg *config.EncryptionConfig, keyProvider types.KeyProvider) (types.Encryptor, error) {
	switch types.Algorithm(cfg.Algorithm) {
	case types.AlgorithmAES256GCM:
		// Use simple implementation for now
		return stream.NewSimpleAESGCMEncryptor(keyProvider), nil

	case types.AlgorithmChaCha20Poly1305:
		// TODO: Implement ChaCha20-Poly1305 encryptor
		return nil, fmt.Errorf("ChaCha20-Poly1305 not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", cfg.Algorithm)
	}
}
