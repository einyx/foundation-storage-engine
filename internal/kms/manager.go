package kms

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Manager handles KMS operations for S3 proxy
type Manager struct {
	client       *kms.Client
	config       *Config
	keyCache     map[string]*KeyInfo
	keyCacheMu   sync.RWMutex
	dataKeyCache *DataKeyCache
}

// Config holds KMS configuration
type Config struct {
	Enabled           bool              `yaml:"enabled" json:"enabled"`
	DefaultKeyID      string            `yaml:"default_key_id" json:"default_key_id"`
	KeySpec           types.DataKeySpec `yaml:"key_spec" json:"key_spec"`
	Region            string            `yaml:"region" json:"region"`
	EncryptionContext map[string]string `yaml:"encryption_context" json:"encryption_context"`
	DataKeyCacheTTL   time.Duration     `yaml:"data_key_cache_ttl" json:"data_key_cache_ttl"`
	ValidateKeys      bool              `yaml:"validate_keys" json:"validate_keys"`
	EnableKeyRotation bool              `yaml:"enable_key_rotation" json:"enable_key_rotation"`
}

// KeyInfo stores validated key information
type KeyInfo struct {
	KeyID           string
	Arn             string
	KeySpec         types.KeySpec
	Enabled         bool
	Description     string
	LastValidated   time.Time
	SupportsEncrypt bool
	SupportsDecrypt bool
}

// BucketKMSConfig holds per-bucket KMS configuration
type BucketKMSConfig struct {
	KeyID             string            `yaml:"kms_key_id" json:"kms_key_id"`
	EncryptionContext map[string]string `yaml:"kms_encryption_context" json:"kms_encryption_context"`
	OverrideDefault   bool              `yaml:"override_default" json:"override_default"`
}

// New creates a new KMS manager
func New(ctx context.Context, cfg *Config) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kms config is nil")
	}

	if !cfg.Enabled {
		return &Manager{config: cfg}, nil
	}

	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := kms.NewFromConfig(awsCfg)

	m := &Manager{
		client:       client,
		config:       cfg,
		keyCache:     make(map[string]*KeyInfo),
		dataKeyCache: NewDataKeyCache(cfg.DataKeyCacheTTL),
	}

	// Validate default key if specified
	if cfg.ValidateKeys && cfg.DefaultKeyID != "" {
		if _, err := m.ValidateKey(ctx, cfg.DefaultKeyID); err != nil {
			return nil, fmt.Errorf("failed to validate default KMS key: %w", err)
		}
	}

	return m, nil
}

// IsEnabled returns whether KMS encryption is enabled
func (m *Manager) IsEnabled() bool {
	if m == nil || m.config == nil {
		return false
	}
	return m.config.Enabled && m.client != nil
}

// GetEncryptionHeaders returns S3 encryption headers for KMS
func (m *Manager) GetEncryptionHeaders(bucket string, bucketConfig *BucketKMSConfig) map[string]string {
	if !m.IsEnabled() {
		return nil
	}

	headers := make(map[string]string, 3) // Pre-allocate for common case
	headers["x-amz-server-side-encryption"] = "aws:kms"

	// Determine which key to use
	keyID := m.config.DefaultKeyID
	encContext := m.config.EncryptionContext

	// Override with bucket-specific config if provided
	if bucketConfig != nil && bucketConfig.KeyID != "" {
		keyID = bucketConfig.KeyID
		if bucketConfig.OverrideDefault || len(bucketConfig.EncryptionContext) > 0 {
			encContext = bucketConfig.EncryptionContext
		}
	}

	if keyID != "" {
		headers["x-amz-server-side-encryption-aws-kms-key-id"] = keyID
	}

	// Add encryption context if provided
	if len(encContext) > 0 {
		contextStr := serializeEncryptionContext(encContext)
		if contextStr != "" {
			headers["x-amz-server-side-encryption-context"] = contextStr
		}
	}

	return headers
}

// ValidateKey validates a KMS key and caches the result
func (m *Manager) ValidateKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	if !m.IsEnabled() {
		return nil, fmt.Errorf("kms is not enabled")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	// Check cache first
	m.keyCacheMu.RLock()
	if info, ok := m.keyCache[keyID]; ok {
		// Cache entries are valid for 1 hour
		if time.Since(info.LastValidated) < time.Hour {
			m.keyCacheMu.RUnlock()
			return info, nil
		}
	}
	m.keyCacheMu.RUnlock()

	// Describe the key
	describeResp, err := m.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe key %s: %w", keyID, err)
	}

	keyMeta := describeResp.KeyMetadata
	if keyMeta == nil {
		return nil, fmt.Errorf("key metadata is nil for key %s", keyID)
	}

	info := &KeyInfo{
		Enabled:       keyMeta.KeyState == types.KeyStateEnabled,
		LastValidated: time.Now(),
	}

	// Safely assign string pointers
	if keyMeta.KeyId != nil {
		info.KeyID = *keyMeta.KeyId
	}
	if keyMeta.Arn != nil {
		info.Arn = *keyMeta.Arn
	}

	if keyMeta.Description != nil {
		info.Description = *keyMeta.Description
	}

	if keyMeta.KeySpec != "" {
		info.KeySpec = keyMeta.KeySpec
	}

	// Check key usage
	if keyMeta.KeyUsage == types.KeyUsageTypeEncryptDecrypt {
		info.SupportsEncrypt = true
		info.SupportsDecrypt = true
	}

	if !info.Enabled {
		return nil, fmt.Errorf("key %s is not enabled (state: %s)", keyID, keyMeta.KeyState)
	}

	if !info.SupportsEncrypt {
		return nil, fmt.Errorf("key %s does not support encryption", keyID)
	}

	// Test key permissions by generating a data key
	_, err = m.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, fmt.Errorf("insufficient permissions for key %s: %w", keyID, err)
	}

	// Cache the validated key info
	m.keyCacheMu.Lock()
	m.keyCache[keyID] = info
	m.keyCacheMu.Unlock()

	return info, nil
}

// GenerateDataKey generates a data key for envelope encryption
func (m *Manager) GenerateDataKey(ctx context.Context, keyID string, context map[string]string) (*DataKey, error) {
	if !m.IsEnabled() {
		return nil, fmt.Errorf("kms is not enabled")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	// Check cache first
	cacheKey := buildDataKeyCacheKey(keyID, context)
	if dataKey := m.dataKeyCache.Get(cacheKey); dataKey != nil {
		return dataKey, nil
	}

	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: types.DataKeySpecAes256,
	}

	if len(context) > 0 {
		input.EncryptionContext = context
	}

	resp, err := m.client.GenerateDataKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Validate response
	if resp == nil || len(resp.Plaintext) == 0 || len(resp.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("invalid response from KMS: missing data key")
	}

	dataKey := &DataKey{
		KeyID:             keyID,
		PlaintextKey:      resp.Plaintext,
		CiphertextBlob:    resp.CiphertextBlob,
		EncryptionContext: context,
		CreatedAt:         time.Now(),
	}

	// Cache the data key
	m.dataKeyCache.Put(cacheKey, dataKey)

	return dataKey, nil
}

// DecryptDataKey decrypts a data key
func (m *Manager) DecryptDataKey(ctx context.Context, ciphertextBlob []byte, context map[string]string) (*DataKey, error) {
	if !m.IsEnabled() {
		return nil, fmt.Errorf("kms is not enabled")
	}

	if len(ciphertextBlob) == 0 {
		return nil, fmt.Errorf("ciphertextBlob cannot be empty")
	}

	input := &kms.DecryptInput{
		CiphertextBlob: ciphertextBlob,
	}

	if len(context) > 0 {
		input.EncryptionContext = context
	}

	resp, err := m.client.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}

	// Validate response
	if resp == nil || len(resp.Plaintext) == 0 {
		return nil, fmt.Errorf("invalid response from KMS: missing plaintext")
	}

	dataKey := &DataKey{
		PlaintextKey:      resp.Plaintext,
		CiphertextBlob:    ciphertextBlob,
		EncryptionContext: context,
		CreatedAt:         time.Now(),
	}

	// Safely assign KeyID if present
	if resp.KeyId != nil {
		dataKey.KeyID = *resp.KeyId
	}

	return dataKey, nil
}

// GetKeyRotationStatus checks if key rotation is enabled
func (m *Manager) GetKeyRotationStatus(ctx context.Context, keyID string) (bool, error) {
	if !m.IsEnabled() {
		return false, fmt.Errorf("kms is not enabled")
	}

	if keyID == "" {
		return false, fmt.Errorf("keyID cannot be empty")
	}

	resp, err := m.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return false, fmt.Errorf("failed to get key rotation status: %w", err)
	}

	return resp.KeyRotationEnabled, nil
}

// EnableKeyRotation enables automatic key rotation
func (m *Manager) EnableKeyRotation(ctx context.Context, keyID string) error {
	if !m.IsEnabled() {
		return fmt.Errorf("kms is not enabled")
	}

	if keyID == "" {
		return fmt.Errorf("keyID cannot be empty")
	}

	_, err := m.client.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return fmt.Errorf("failed to enable key rotation: %w", err)
	}

	return nil
}

// Close cleans up resources
func (m *Manager) Close() {
	if m == nil {
		return
	}

	if m.dataKeyCache != nil {
		m.dataKeyCache.Close()
	}

	// Clear key cache to free memory
	m.keyCacheMu.Lock()
	m.keyCache = nil
	m.keyCacheMu.Unlock()
}
