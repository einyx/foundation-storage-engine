package kms

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Enabled:      true,
				DefaultKeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				KeySpec:      types.DataKeySpecAes256,
				Region:       "us-east-1",
				EncryptionContext: map[string]string{
					"app": "s3proxy",
				},
				DataKeyCacheTTL: 5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetEncryptionHeaders(t *testing.T) {
	// Create a mock KMS client to simulate enabled state
	mockClient := &kms.Client{}

	manager := &Manager{
		config: &Config{
			Enabled:      true,
			DefaultKeyID: "alias/default-key",
			EncryptionContext: map[string]string{
				"app": "s3proxy",
			},
		},
		client: mockClient, // Set non-nil client to pass IsEnabled check
	}

	tests := []struct {
		name         string
		bucket       string
		bucketConfig *BucketKMSConfig
		wantHeaders  map[string]string
	}{
		{
			name:   "default key",
			bucket: "test-bucket",
			wantHeaders: map[string]string{
				"x-amz-server-side-encryption":                "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id": "alias/default-key",
				"x-amz-server-side-encryption-context":        "app=s3proxy",
			},
		},
		{
			name:   "bucket-specific key",
			bucket: "secure-bucket",
			bucketConfig: &BucketKMSConfig{
				KeyID: "alias/secure-bucket-key",
				EncryptionContext: map[string]string{
					"bucket": "secure-bucket",
					"env":    "prod",
				},
				OverrideDefault: true,
			},
			wantHeaders: map[string]string{
				"x-amz-server-side-encryption":                "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id": "alias/secure-bucket-key",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := manager.GetEncryptionHeaders(tt.bucket, tt.bucketConfig)

			// Check required headers
			assert.Equal(t, tt.wantHeaders["x-amz-server-side-encryption"], headers["x-amz-server-side-encryption"])
			assert.Equal(t, tt.wantHeaders["x-amz-server-side-encryption-aws-kms-key-id"], headers["x-amz-server-side-encryption-aws-kms-key-id"])

			// Check encryption context if present
			if _, ok := tt.wantHeaders["x-amz-server-side-encryption-context"]; ok {
				assert.NotEmpty(t, headers["x-amz-server-side-encryption-context"])
			}
		})
	}
}

func TestDataKeyCache(t *testing.T) {
	cache := NewDataKeyCache(100 * time.Millisecond)
	defer cache.Close()

	dataKey := &DataKey{
		KeyID:          "test-key",
		PlaintextKey:   []byte("test-plaintext-key"),
		CiphertextBlob: []byte("test-ciphertext"),
		EncryptionContext: map[string]string{
			"test": "context",
		},
		CreatedAt: time.Now(),
	}

	// Test Put and Get
	cacheKey := buildDataKeyCacheKey("test-key", dataKey.EncryptionContext)
	cache.Put(cacheKey, dataKey)

	retrieved := cache.Get(cacheKey)
	require.NotNil(t, retrieved)
	assert.Equal(t, dataKey.KeyID, retrieved.KeyID)

	// Test expiration
	time.Sleep(150 * time.Millisecond)
	expired := cache.Get(cacheKey)
	assert.Nil(t, expired)

	// Test cleanup
	cache.Clear() // Clear cache first to ensure clean state
	cache.Put("key1", dataKey)
	cache.Put("key2", dataKey)
	assert.Equal(t, 2, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
}

func TestSerializeEncryptionContext(t *testing.T) {
	tests := []struct {
		name     string
		context  map[string]string
		expected string
		notEmpty bool
	}{
		{
			name:     "empty context",
			context:  map[string]string{},
			expected: "",
		},
		{
			name: "single key",
			context: map[string]string{
				"bucket": "test",
			},
			notEmpty: true,
		},
		{
			name: "multiple keys",
			context: map[string]string{
				"bucket": "test",
				"env":    "prod",
			},
			notEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := serializeEncryptionContext(tt.context)
			if tt.expected != "" {
				assert.Equal(t, tt.expected, result)
			} else if tt.notEmpty {
				assert.NotEmpty(t, result)
			} else {
				assert.Empty(t, result)
			}
		})
	}
}

func TestKMSError(t *testing.T) {
	err := &KMSError{
		Op:        "GenerateDataKey",
		KeyID:     "test-key",
		Err:       ErrInsufficientPermissions,
		Retryable: false,
	}

	assert.Contains(t, err.Error(), "GenerateDataKey")
	assert.Contains(t, err.Error(), "test-key")
	assert.Equal(t, ErrInsufficientPermissions, err.Unwrap())
	assert.False(t, err.IsRetryable())

	// Test IsKMSError
	assert.True(t, IsKMSError(err))
	assert.False(t, IsKMSError(ErrKMSNotEnabled))

	// Test WrapError
	wrapped := WrapError("Decrypt", "key-123", ErrKeyNotFound, true)
	assert.True(t, IsKMSError(wrapped))
	assert.True(t, IsRetryableError(wrapped))
}
