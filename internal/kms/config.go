package kms

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

// ConfigFromAppConfig converts application config to KMS config
func ConfigFromAppConfig(cfg *config.KMSKeyConfig) (*Config, error) {
	if cfg == nil {
		return &Config{Enabled: false}, nil
	}

	// Parse data key cache TTL
	cacheTTL, err := time.ParseDuration(cfg.DataKeyCacheTTL)
	if err != nil {
		cacheTTL = 5 * time.Minute // Default
	}

	// Convert key spec string to AWS type
	var keySpec types.DataKeySpec
	switch cfg.KeySpec {
	case "AES_128":
		keySpec = types.DataKeySpecAes128
	case "AES_256", "":
		keySpec = types.DataKeySpecAes256
	default:
		keySpec = types.DataKeySpecAes256
	}

	return &Config{
		Enabled:           cfg.Enabled,
		DefaultKeyID:      cfg.DefaultKeyID,
		KeySpec:           keySpec,
		Region:            cfg.Region,
		EncryptionContext: cfg.EncryptionContext,
		DataKeyCacheTTL:   cacheTTL,
		ValidateKeys:      cfg.ValidateKeys,
		EnableKeyRotation: cfg.EnableKeyRotation,
	}, nil
}

// BucketConfigFromAppConfig converts application bucket config to KMS bucket config
func BucketConfigFromAppConfig(cfg *config.BucketConfig) *BucketKMSConfig {
	if cfg == nil || cfg.KMSKeyID == "" {
		return nil
	}

	return &BucketKMSConfig{
		KeyID:             cfg.KMSKeyID,
		EncryptionContext: cfg.KMSEncryptionContext,
		OverrideDefault:   len(cfg.KMSEncryptionContext) > 0,
	}
}
