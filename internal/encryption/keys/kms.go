// Package keys provides key management implementations for encryption.
package keys

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSKeyProvider provides AWS KMS key management
type KMSKeyProvider struct {
	client      *kms.Client
	keyID       string
	cacheExpiry time.Duration
}

// NewKMSKeyProvider creates a new AWS KMS key provider
func NewKMSKeyProvider(cfg aws.Config, keyID string) (*KMSKeyProvider, error) {
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}

	return &KMSKeyProvider{
		client:      kms.NewFromConfig(cfg),
		keyID:       keyID,
		cacheExpiry: 5 * time.Minute,
	}, nil
}

// GenerateDEK generates a new data encryption key using AWS KMS
func (p *KMSKeyProvider) GenerateDEK(ctx context.Context) ([]byte, string, error) {
	// Request a data key from KMS
	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(p.keyID),
		KeySpec: types.DataKeySpecAes256,
		EncryptionContext: map[string]string{
			"purpose":   "s3proxy-encryption",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}

	result, err := p.client.GenerateDataKey(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate data key: %w", err)
	}

	// Return plaintext key and base64-encoded ciphertext
	encryptedKey := base64.StdEncoding.EncodeToString(result.CiphertextBlob)

	return result.Plaintext, encryptedKey, nil
}

// DecryptDEK decrypts an encrypted data encryption key using AWS KMS
func (p *KMSKeyProvider) DecryptDEK(ctx context.Context, encryptedKey string) ([]byte, error) {
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	// Decrypt using KMS
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		EncryptionContext: map[string]string{
			"purpose": "s3proxy-encryption",
		},
		KeyId: aws.String(p.keyID),
	}

	result, err := p.client.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}

	return result.Plaintext, nil
}

// Name returns the provider name
func (p *KMSKeyProvider) Name() string {
	return "aws-kms"
}

// SetCacheExpiry sets the cache expiry duration for DEKs
func (p *KMSKeyProvider) SetCacheExpiry(duration time.Duration) {
	p.cacheExpiry = duration
}
