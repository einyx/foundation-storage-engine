// Package encryption provides encryption management for S3 objects
package encryption

import (
	"context"
	"fmt"
	"io"

	"github.com/einyx/s3proxy-go/internal/encryption/types"
)

// Manager coordinates encryption operations
type Manager struct {
	keyProvider types.KeyProvider
	encryptor   types.Encryptor
	enabled     bool
}

// NewManager creates a new encryption manager
func NewManager(keyProvider types.KeyProvider, encryptor types.Encryptor, enabled bool) *Manager {
	return &Manager{
		keyProvider: keyProvider,
		encryptor:   encryptor,
		enabled:     enabled,
	}
}

// IsEnabled returns whether encryption is enabled
func (m *Manager) IsEnabled() bool {
	return m.enabled
}

// Encrypt wraps a reader with encryption if enabled
func (m *Manager) Encrypt(ctx context.Context, reader io.Reader, size int64) (io.Reader, map[string]string, error) {
	if !m.enabled {
		return reader, nil, nil
	}

	return m.encryptor.Encrypt(ctx, reader, size)
}

// Decrypt wraps a reader with decryption if needed
func (m *Manager) Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
	// Check if object is encrypted
	if metadata[types.MetadataKeyAlgorithm] == "" {
		// Not encrypted, return original reader
		return reader, nil
	}

	if !m.enabled {
		return nil, fmt.Errorf("encryption is disabled but object is encrypted")
	}

	return m.encryptor.Decrypt(ctx, reader, metadata)
}

// ShouldEncrypt determines if an object should be encrypted based on bucket policies
func (m *Manager) ShouldEncrypt(_ string) bool {
	if !m.enabled {
		return false
	}

	// TODO: Implement bucket-specific policies
	// For now, encrypt everything when enabled
	return true
}

// GetKeyProvider returns the current key provider
func (m *Manager) GetKeyProvider() types.KeyProvider {
	return m.keyProvider
}

// GetEncryptor returns the current encryptor
func (m *Manager) GetEncryptor() types.Encryptor {
	return m.encryptor
}
