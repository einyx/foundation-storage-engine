//go:build integration
// +build integration

package kms

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKMSIntegration tests real KMS operations
// Run with: go test -tags=integration ./internal/kms
func TestKMSIntegration(t *testing.T) {
	// Skip if not running integration tests
	keyID := os.Getenv("TEST_KMS_KEY_ID")
	if keyID == "" {
		t.Skip("TEST_KMS_KEY_ID not set, skipping integration test")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	config := &Config{
		Enabled:      true,
		DefaultKeyID: keyID,
		KeySpec:      types.KeySpecAes256,
		Region:       region,
		EncryptionContext: map[string]string{
			"application": "s3proxy-test",
			"environment": "test",
		},
		DataKeyCacheTTL: 1 * time.Minute,
		ValidateKeys:    true,
	}

	ctx := context.Background()
	manager, err := New(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	t.Run("ValidateKey", func(t *testing.T) {
		info, err := manager.ValidateKey(ctx, keyID)
		require.NoError(t, err)
		assert.NotNil(t, info)
		assert.Equal(t, keyID, info.KeyID)
		assert.True(t, info.Enabled)
		assert.True(t, info.SupportsEncrypt)
		assert.True(t, info.SupportsDecrypt)
	})

	t.Run("GenerateDataKey", func(t *testing.T) {
		dataKey, err := manager.GenerateDataKey(ctx, keyID, config.EncryptionContext)
		require.NoError(t, err)
		assert.NotNil(t, dataKey)
		assert.NotEmpty(t, dataKey.PlaintextKey)
		assert.NotEmpty(t, dataKey.CiphertextBlob)
		assert.Equal(t, 32, len(dataKey.PlaintextKey)) // AES-256
	})

	t.Run("DecryptDataKey", func(t *testing.T) {
		// First generate a data key
		dataKey1, err := manager.GenerateDataKey(ctx, keyID, config.EncryptionContext)
		require.NoError(t, err)

		// Then decrypt it
		dataKey2, err := manager.DecryptDataKey(ctx, dataKey1.CiphertextBlob, config.EncryptionContext)
		require.NoError(t, err)
		assert.Equal(t, dataKey1.PlaintextKey, dataKey2.PlaintextKey)
	})

	t.Run("EncryptionHeaders", func(t *testing.T) {
		headers := manager.GetEncryptionHeaders("test-bucket", nil)
		assert.Equal(t, "aws:kms", headers["x-amz-server-side-encryption"])
		assert.Equal(t, keyID, headers["x-amz-server-side-encryption-aws-kms-key-id"])
		assert.Contains(t, headers["x-amz-server-side-encryption-context"], "application=s3proxy-test")
	})

	t.Run("BucketSpecificKMS", func(t *testing.T) {
		bucketConfig := &BucketKMSConfig{
			KeyID: keyID,
			EncryptionContext: map[string]string{
				"bucket":         "sensitive-data",
				"classification": "confidential",
			},
			OverrideDefault: true,
		}

		headers := manager.GetEncryptionHeaders("sensitive-data", bucketConfig)
		assert.Equal(t, "aws:kms", headers["x-amz-server-side-encryption"])
		assert.Equal(t, keyID, headers["x-amz-server-side-encryption-aws-kms-key-id"])
		assert.Contains(t, headers["x-amz-server-side-encryption-context"], "bucket=sensitive-data")
		assert.Contains(t, headers["x-amz-server-side-encryption-context"], "classification=confidential")
	})

	t.Run("DataKeyCache", func(t *testing.T) {
		// Generate a data key
		dataKey1, err := manager.GenerateDataKey(ctx, keyID, config.EncryptionContext)
		require.NoError(t, err)

		// Second call should come from cache (verify by timing)
		start := time.Now()
		dataKey2, err := manager.GenerateDataKey(ctx, keyID, config.EncryptionContext)
		duration := time.Since(start)
		require.NoError(t, err)
		assert.Equal(t, dataKey1.PlaintextKey, dataKey2.PlaintextKey)
		assert.Less(t, duration, 10*time.Millisecond) // Cache hit should be fast
	})

	t.Run("KeyRotationStatus", func(t *testing.T) {
		// This may fail if the key doesn't support rotation
		rotationEnabled, err := manager.GetKeyRotationStatus(ctx, keyID)
		if err == nil {
			t.Logf("Key rotation enabled: %v", rotationEnabled)
		} else {
			t.Logf("Key rotation status check failed (may be expected): %v", err)
		}
	})
}

// TestEnvelopeEncryption tests envelope encryption functionality
func TestEnvelopeEncryption(t *testing.T) {
	// Mock KMS manager for unit testing
	manager := &Manager{
		config: &Config{
			Enabled:      true,
			DefaultKeyID: "test-key",
		},
		keyCache:     make(map[string]*KeyInfo),
		dataKeyCache: NewDataKeyCache(5 * time.Minute),
	}

	encryptor := NewEnvelopeEncryptor(manager)

	t.Run("EncryptDecrypt", func(t *testing.T) {
		// Skip if not enabled
		if !manager.IsEnabled() {
			manager.config.Enabled = true
			manager.client = nil // Would be mocked in real test
		}

		// This would need a mock KMS client to work without real AWS
		t.Skip("Requires mock KMS client")
	})
}
