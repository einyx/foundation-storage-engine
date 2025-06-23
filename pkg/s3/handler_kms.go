package s3

import (
	"context"

	"github.com/meshxdata/foundation-storage-engine/internal/auth"
	"github.com/meshxdata/foundation-storage-engine/internal/config"
	"github.com/meshxdata/foundation-storage-engine/internal/kms"
	"github.com/meshxdata/foundation-storage-engine/internal/storage"
)

// HandlerWithKMS extends the base Handler with KMS encryption support
type HandlerWithKMS struct {
	*Handler
	kmsManager *kms.Manager
	kmsConfig  *config.KMSKeyConfig
}

// NewHandlerWithKMS creates a new S3 handler with KMS support
func NewHandlerWithKMS(storage storage.Backend, auth auth.Provider, s3cfg config.S3Config, kmsCfg *config.KMSKeyConfig) (*HandlerWithKMS, error) {
	// Create default chunking config for KMS handler
	chunkingCfg := config.ChunkingConfig{
		VerifySignatures:  false,
		MaxChunkSize:      1048576,
		RequestTimeWindow: 300,
		LogOnlyMode:       true,
	}
	baseHandler := NewHandler(storage, auth, s3cfg, chunkingCfg)

	var kmsManager *kms.Manager
	if kmsCfg != nil && kmsCfg.Enabled {
		kmsConfig, err := kms.ConfigFromAppConfig(kmsCfg)
		if err != nil {
			return nil, err
		}

		kmsManager, err = kms.New(context.Background(), kmsConfig)
		if err != nil {
			return nil, err
		}
	}

	return &HandlerWithKMS{
		Handler:    baseHandler,
		kmsManager: kmsManager,
		kmsConfig:  kmsCfg,
	}, nil
}

// Close cleans up KMS resources
func (h *HandlerWithKMS) Close() {
	if h.kmsManager != nil {
		h.kmsManager.Close()
	}
}
