package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// V4StreamingVerifier verifies AWS Signature V4 streaming chunks
type V4StreamingVerifier struct {
	accessKey  string
	secretKey  string
	region     string
	service    string
	date       string
	seedSig    string
	prevSig    string
	credential string
}

// ParseAuthorizationHeader extracts V4 auth components
func ParseAuthorizationHeader(authHeader string) (map[string]string, error) {
	// Format: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	parts := strings.Split(authHeader[18:], ", ")
	result := make(map[string]string)

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		result[kv[0]] = kv[1]
	}

	return result, nil
}

// NewV4StreamingVerifier creates a new streaming signature verifier
func NewV4StreamingVerifier(authHeader, dateStr, secretKey string) (*V4StreamingVerifier, error) {
	authParts, err := ParseAuthorizationHeader(authHeader)
	if err != nil {
		return nil, err
	}

	credential := authParts["Credential"]
	if credential == "" {
		return nil, fmt.Errorf("missing credential in authorization header")
	}

	// Parse credential: accessKey/date/region/service/aws4_request
	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 {
		return nil, fmt.Errorf("invalid credential format")
	}

	seedSig := authParts["Signature"]
	if seedSig == "" {
		return nil, fmt.Errorf("missing signature in authorization header")
	}

	return &V4StreamingVerifier{
		accessKey:  credParts[0],
		secretKey:  secretKey,
		date:       credParts[1],
		region:     credParts[2],
		service:    credParts[3],
		seedSig:    seedSig,
		prevSig:    seedSig,
		credential: credential,
	}, nil
}

// VerifyChunk verifies a chunk's signature
func (v *V4StreamingVerifier) VerifyChunk(chunkData []byte, chunkSig string) error {
	expectedSig := v.calculateChunkSignature(chunkData)

	if chunkSig != expectedSig {
		return fmt.Errorf("chunk signature mismatch: expected %s, got %s", expectedSig, chunkSig)
	}

	// Update signature chain
	v.prevSig = chunkSig
	return nil
}

// calculateChunkSignature computes the expected signature for a chunk
func (v *V4StreamingVerifier) calculateChunkSignature(chunkData []byte) string {
	// Create string to sign
	stringToSign := v.createChunkStringToSign(chunkData)

	// Derive signing key
	signingKey := v.deriveSigningKey()

	// Calculate signature
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(stringToSign))

	return hex.EncodeToString(h.Sum(nil))
}

// createChunkStringToSign creates the string to sign for a chunk
func (v *V4StreamingVerifier) createChunkStringToSign(chunkData []byte) string {
	// Calculate chunk hash
	chunkHash := sha256.Sum256(chunkData)

	// Format:
	// AWS4-HMAC-SHA256-PAYLOAD
	// date
	// scope
	// previous-signature
	// hash(empty-string) - for no additional headers
	// hash(chunk-data)

	emptyHash := sha256.Sum256([]byte{})

	return fmt.Sprintf("AWS4-HMAC-SHA256-PAYLOAD\n%s\n%s\n%s\n%s\n%s",
		v.date+"T000000Z", // Assuming date format YYYYMMDD
		v.scope(),
		v.prevSig,
		hex.EncodeToString(emptyHash[:]),
		hex.EncodeToString(chunkHash[:]))
}

// scope returns the credential scope
func (v *V4StreamingVerifier) scope() string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", v.date, v.region, v.service)
}

// deriveSigningKey derives the signing key for the request
func (v *V4StreamingVerifier) deriveSigningKey() []byte {
	// AWS4 signing key derivation
	kDate := v4HmacSHA256([]byte("AWS4"+v.secretKey), []byte(v.date))
	kRegion := v4HmacSHA256(kDate, []byte(v.region))
	kService := v4HmacSHA256(kRegion, []byte(v.service))
	kSigning := v4HmacSHA256(kService, []byte("aws4_request"))

	return kSigning
}

// v4HmacSHA256 computes HMAC-SHA256 for V4 signatures
func v4HmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ValidateRequestTime checks if the request is within the allowed time window
func ValidateRequestTime(dateStr string, maxAge time.Duration) error {
	// Parse AWS date format: YYYYMMDDTHHMMSSZ
	layout := "20060102T150405Z"

	requestTime, err := time.Parse(layout, dateStr)
	if err != nil {
		return fmt.Errorf("invalid date format: %w", err)
	}

	age := time.Since(requestTime)
	if age > maxAge || age < -maxAge {
		return fmt.Errorf("request time too old: %v", age)
	}

	return nil
}
