package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSProvider implements Provider interface for AWS KMS
type AWSKMSProvider struct {
	client            *kms.Client
	encryptionContext map[string]string
	dataKeyCache      *DataKeyCache
	keySpec           types.DataKeySpec
}

// NewAWSKMSProvider creates a new AWS KMS provider
func NewAWSKMSProvider(ctx context.Context, config map[string]interface{}) (Provider, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Extract configuration with safe type assertions
	region, _ := config["region"].(string)
	encryptionContext := make(map[string]string)
	if ec, ok := config["encryption_context"].(map[string]interface{}); ok {
		for k, v := range ec {
			if vs, ok := v.(string); ok {
				encryptionContext[k] = vs
			}
		}
	}

	// Parse key spec
	keySpec := types.DataKeySpecAes256
	if ks, ok := config["key_spec"].(string); ok {
		switch ks {
		case "AES_128":
			keySpec = types.DataKeySpecAes128
		case "AES_256":
			keySpec = types.DataKeySpecAes256
		}
	}

	// Load AWS configuration
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Override region if specified
	if region != "" {
		awsCfg.Region = region
	}

	// Create KMS client
	client := kms.NewFromConfig(awsCfg)

	// Create data key cache
	cacheTTL := 5 * time.Minute
	if ttl, ok := config["data_key_cache_ttl"].(string); ok {
		if d, err := time.ParseDuration(ttl); err == nil {
			cacheTTL = d
		}
	}

	return &AWSKMSProvider{
		client:            client,
		encryptionContext: encryptionContext,
		dataKeyCache:      NewDataKeyCache(cacheTTL),
		keySpec:           keySpec,
	}, nil
}

// Name returns the provider name
func (p *AWSKMSProvider) Name() string {
	return string(ProviderTypeAWSKMS)
}

// GenerateDataKey generates a new data encryption key
func (p *AWSKMSProvider) GenerateDataKey(ctx context.Context, keyID string, keySpec string) (*ProviderDataKey, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("provider not initialized")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Check cache first
	if p.dataKeyCache != nil {
		if cachedKey := p.dataKeyCache.Get(keyID); cachedKey != nil {
			return &ProviderDataKey{
				Plaintext:      cachedKey.PlaintextKey,
				CiphertextBlob: cachedKey.CiphertextBlob,
				KeyID:          keyID,
				Provider:       p.Name(),
			}, nil
		}
	}

	// Parse key spec if provided
	spec := p.keySpec
	if keySpec != "" {
		switch keySpec {
		case "AES_128":
			spec = types.DataKeySpecAes128
		case "AES_256":
			spec = types.DataKeySpecAes256
		}
	}

	// Generate new data key
	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: spec,
	}

	if len(p.encryptionContext) > 0 {
		input.EncryptionContext = p.encryptionContext
	}

	output, err := p.client.GenerateDataKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Validate output
	if output == nil || len(output.Plaintext) == 0 || len(output.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("invalid response from KMS: missing data key")
	}

	dataKey := &ProviderDataKey{
		Plaintext:      output.Plaintext,
		CiphertextBlob: output.CiphertextBlob,
		KeyID:          keyID,
		Provider:       p.Name(),
	}

	// Cache the key if cache is available
	if p.dataKeyCache != nil {
		p.dataKeyCache.Put(keyID, &DataKey{
			PlaintextKey:   output.Plaintext,
			CiphertextBlob: output.CiphertextBlob,
			KeyID:          keyID,
			CreatedAt:      time.Now(),
		})
	}

	return dataKey, nil
}

// Decrypt decrypts the encrypted data key
func (p *AWSKMSProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("provider not initialized")
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}

	if len(p.encryptionContext) > 0 {
		input.EncryptionContext = p.encryptionContext
	}

	output, err := p.client.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}

	// Validate output
	if output == nil || len(output.Plaintext) == 0 {
		return nil, fmt.Errorf("invalid response from KMS: missing plaintext")
	}

	return output.Plaintext, nil
}

// ValidateKey validates that a key exists and is usable
func (p *AWSKMSProvider) ValidateKey(ctx context.Context, keyID string) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("provider not initialized")
	}

	if keyID == "" {
		return fmt.Errorf("keyID cannot be empty")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	output, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return fmt.Errorf("failed to describe key: %w", err)
	}

	if output.KeyMetadata == nil {
		return fmt.Errorf("key metadata is nil")
	}

	if output.KeyMetadata.KeyState != types.KeyStateEnabled {
		return fmt.Errorf("key %s is not enabled (state: %s)", keyID, output.KeyMetadata.KeyState)
	}

	if output.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return fmt.Errorf("key %s does not support encryption/decryption (usage: %s)", keyID, output.KeyMetadata.KeyUsage)
	}

	return nil
}

// GetKeyInfo retrieves information about a key
func (p *AWSKMSProvider) GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("provider not initialized")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be empty")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	output, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe key: %w", err)
	}

	if output.KeyMetadata == nil {
		return nil, fmt.Errorf("key metadata is nil")
	}

	keyMeta := output.KeyMetadata
	info := &KeyInfo{
		KeyID:         keyID,
		Enabled:       keyMeta.KeyState == types.KeyStateEnabled,
		LastValidated: time.Now(),
	}

	// Safely assign optional fields
	if keyMeta.Arn != nil {
		info.Arn = aws.ToString(keyMeta.Arn)
	}

	if keyMeta.Description != nil {
		info.Description = aws.ToString(keyMeta.Description)
	}

	if keyMeta.KeySpec != "" {
		info.KeySpec = keyMeta.KeySpec
	}

	if keyMeta.KeyUsage == types.KeyUsageTypeEncryptDecrypt {
		info.SupportsEncrypt = true
		info.SupportsDecrypt = true
	}

	return info, nil
}
