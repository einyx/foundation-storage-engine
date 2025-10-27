package s3

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatePutObjectRequest(t *testing.T) {
	tests := []struct {
		name           string
		bucket         string
		key            string
		contentLength  int64
		headers        map[string]string
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name:          "valid_standard_request",
			bucket:        "warehouse",
			key:           "data/file.parquet",
			contentLength: 1024,
			wantErr:       false,
		},
		{
			name:          "valid_chunked_request",
			bucket:        "warehouse", 
			key:           "data/file.parquet",
			contentLength: -1,
			headers: map[string]string{
				"Transfer-Encoding": "chunked",
			},
			wantErr: false,
		},
		{
			name:           "invalid_bucket_empty",
			bucket:         "",
			key:            "data/file.parquet",
			contentLength:  1024,
			wantErr:        true,
			expectedErrMsg: "invalid bucket name",
		},
		{
			name:           "invalid_key_empty",
			bucket:         "warehouse",
			key:            "",
			contentLength:  1024,
			wantErr:        true,
			expectedErrMsg: "invalid object key",
		},
		{
			name:           "missing_content_length",
			bucket:         "warehouse",
			key:            "data/file.parquet",
			contentLength:  -1,
			wantErr:        true,
			expectedErrMsg: "missing Content-Length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/"+tt.bucket+"/"+tt.key, nil)
			req.ContentLength = tt.contentLength
			
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			err := validatePutObjectRequest(tt.bucket, tt.key, req)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("validatePutObjectRequest() expected error but got none")
				} else if tt.expectedErrMsg != "" && !strings.Contains(err.Error(), tt.expectedErrMsg) {
					t.Errorf("validatePutObjectRequest() error = %v, expected to contain %v", err, tt.expectedErrMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validatePutObjectRequest() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestExtractPutRequestContext(t *testing.T) {
	tests := []struct {
		name     string
		bucket   string
		key      string
		headers  map[string]string
		expected *PutRequestContext
	}{
		{
			name:   "standard_parquet_upload",
			bucket: "warehouse",
			key:    "events/data/file.parquet",
			headers: map[string]string{
				"Content-Type":   "application/octet-stream",
				"Content-Length": "1048576",
				"User-Agent":     "Spark/3.4.0",
			},
			expected: &PutRequestContext{
				Bucket:            "warehouse",
				Key:               "events/data/file.parquet",
				ContentLength:     1048576,
				ContentType:       "application/octet-stream",
				UserAgent:         "Spark/3.4.0",
				IsChunkedTransfer: false,
				IsIcebergMeta:     false,
				IsIcebergManifest: false,
				IsIcebergData:     true,
				IsJavaClient:      true,
				IsAWSCLI:          false,
				ChunkedWithoutSize: false,
			},
		},
		{
			name:   "iceberg_metadata_chunked",
			bucket: "warehouse",
			key:    "events/metadata/v1.metadata.json",
			headers: map[string]string{
				"Content-Type":        "application/json",
				"User-Agent":          "aws-sdk-java/2.30.12 app/Trino",
				"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			},
			expected: &PutRequestContext{
				Bucket:            "warehouse",
				Key:               "events/metadata/v1.metadata.json",
				ContentType:       "application/json",
				ContentSHA256:     "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
				UserAgent:         "aws-sdk-java/2.30.12 app/Trino",
				IsChunkedTransfer: true,
				IsIcebergMeta:     true,
				IsIcebergManifest: false,
				IsIcebergData:     false,
				IsJavaClient:      true,
				IsAWSCLI:          false,
			},
		},
		{
			name:   "aws_cli_upload",
			bucket: "warehouse",
			key:    "uploads/document.pdf",
			headers: map[string]string{
				"Content-Type":   "application/pdf",
				"Content-Length": "2048000",
				"User-Agent":     "aws-cli/2.0.0",
			},
			expected: &PutRequestContext{
				Bucket:            "warehouse",
				Key:               "uploads/document.pdf",
				ContentLength:     2048000,
				ContentType:       "application/pdf",
				UserAgent:         "aws-cli/2.0.0",
				IsChunkedTransfer: false,
				IsIcebergMeta:     false,
				IsIcebergManifest: false,
				IsIcebergData:     false,
				IsJavaClient:      false,
				IsAWSCLI:          true,
				ChunkedWithoutSize: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/"+tt.bucket+"/"+tt.key, nil)
			
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			
			// Set ContentLength from header if provided
			if contentLengthStr := tt.headers["Content-Length"]; contentLengthStr != "" {
				// httptest automatically parses Content-Length header
			}

			ctx := extractPutRequestContext(tt.bucket, tt.key, req)

			// Compare important fields
			if ctx.Bucket != tt.expected.Bucket {
				t.Errorf("Bucket = %v, want %v", ctx.Bucket, tt.expected.Bucket)
			}
			if ctx.Key != tt.expected.Key {
				t.Errorf("Key = %v, want %v", ctx.Key, tt.expected.Key)
			}
			if ctx.ContentType != tt.expected.ContentType {
				t.Errorf("ContentType = %v, want %v", ctx.ContentType, tt.expected.ContentType)
			}
			if ctx.UserAgent != tt.expected.UserAgent {
				t.Errorf("UserAgent = %v, want %v", ctx.UserAgent, tt.expected.UserAgent)
			}
			if ctx.IsChunkedTransfer != tt.expected.IsChunkedTransfer {
				t.Errorf("IsChunkedTransfer = %v, want %v", ctx.IsChunkedTransfer, tt.expected.IsChunkedTransfer)
			}
			if ctx.IsIcebergMeta != tt.expected.IsIcebergMeta {
				t.Errorf("IsIcebergMeta = %v, want %v", ctx.IsIcebergMeta, tt.expected.IsIcebergMeta)
			}
			if ctx.IsIcebergData != tt.expected.IsIcebergData {
				t.Errorf("IsIcebergData = %v, want %v", ctx.IsIcebergData, tt.expected.IsIcebergData)
			}
			if ctx.IsJavaClient != tt.expected.IsJavaClient {
				t.Errorf("IsJavaClient = %v, want %v", ctx.IsJavaClient, tt.expected.IsJavaClient)
			}
			if ctx.IsAWSCLI != tt.expected.IsAWSCLI {
				t.Errorf("IsAWSCLI = %v, want %v", ctx.IsAWSCLI, tt.expected.IsAWSCLI)
			}
		})
	}
}

func TestExtractRequestMetadata(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected map[string]string
	}{
		{
			name: "standard_headers",
			headers: map[string]string{
				"Content-Type":     "application/json",
				"Content-Encoding": "gzip",
				"Cache-Control":    "max-age=3600",
				"x-amz-meta-user":  "testuser",
				"x-amz-meta-env":   "production",
			},
			expected: map[string]string{
				"Content-Type":     "application/json",
				"Content-Encoding": "gzip",
				"Cache-Control":    "max-age=3600",
				"x-amz-meta-user":  "testuser",
				"x-amz-meta-env":   "production",
			},
		},
		{
			name: "empty_headers",
			headers: map[string]string{},
			expected: map[string]string{},
		},
		{
			name: "ignored_headers",
			headers: map[string]string{
				"Authorization": "Bearer token",
				"Host":         "localhost",
				"User-Agent":   "test-client",
			},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/bucket/key", nil)
			
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			metadata := extractRequestMetadata(req)

			for key, expectedValue := range tt.expected {
				if actualValue, ok := metadata[key]; !ok {
					t.Errorf("Expected metadata key %v not found", key)
				} else if actualValue != expectedValue {
					t.Errorf("Metadata[%v] = %v, want %v", key, actualValue, expectedValue)
				}
			}

			// Check no unexpected keys
			for key := range metadata {
				if _, expected := tt.expected[key]; !expected {
					t.Errorf("Unexpected metadata key %v found", key)
				}
			}
		})
	}
}

func TestCalculateActualSize(t *testing.T) {
	tests := []struct {
		name                  string
		contentLength         int64
		decodedContentLength  string
		expectedSize          int64
		wantErr               bool
		expectedErrMsg        string
	}{
		{
			name:          "standard_content_length",
			contentLength: 1024,
			expectedSize:  1024,
			wantErr:       false,
		},
		{
			name:                 "decoded_content_length",
			contentLength:        1500,
			decodedContentLength: "1024",
			expectedSize:         1024,
			wantErr:              false,
		},
		{
			name:                 "invalid_decoded_length",
			contentLength:        1024,
			decodedContentLength: "invalid",
			wantErr:              true,
			expectedErrMsg:       "invalid decoded content length",
		},
		{
			name:           "negative_content_length",
			contentLength:  -1,
			wantErr:        true,
			expectedErrMsg: "invalid content length",
		},
		{
			name:           "too_large_object",
			contentLength:  6 * 1024 * 1024 * 1024, // 6GB > 5GB limit
			wantErr:        true,
			expectedErrMsg: "object too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSize, err := calculateActualSize(tt.contentLength, tt.decodedContentLength)

			if tt.wantErr {
				if err == nil {
					t.Errorf("calculateActualSize() expected error but got none")
				} else if tt.expectedErrMsg != "" && !strings.Contains(err.Error(), tt.expectedErrMsg) {
					t.Errorf("calculateActualSize() error = %v, expected to contain %v", err, tt.expectedErrMsg)
				}
			} else {
				if err != nil {
					t.Errorf("calculateActualSize() unexpected error = %v", err)
				}
				if actualSize != tt.expectedSize {
					t.Errorf("calculateActualSize() = %v, want %v", actualSize, tt.expectedSize)
				}
			}
		})
	}
}

func TestDetermineReadStrategy(t *testing.T) {
	tests := []struct {
		name             string
		ctx              *PutRequestContext
		actualSize       int64
		expectedStrategy ReadStrategy
	}{
		{
			name: "small_standard_file",
			ctx: &PutRequestContext{
				IsChunkedTransfer: false,
				IsAWSCLI:          false,
			},
			actualSize:       50 * 1024, // 50KB
			expectedStrategy: ReadStrategyStandardSmall,
		},
		{
			name: "small_chunked_file_non_aws_cli",
			ctx: &PutRequestContext{
				IsChunkedTransfer: true,
				IsAWSCLI:          false,
			},
			actualSize:       50 * 1024, // 50KB
			expectedStrategy: ReadStrategyChunkedSmall,
		},
		{
			name: "small_chunked_file_aws_cli",
			ctx: &PutRequestContext{
				IsChunkedTransfer: true,
				IsAWSCLI:          true,
			},
			actualSize:       50 * 1024, // 50KB
			expectedStrategy: ReadStrategyStandardSmall,
		},
		{
			name: "large_standard_file",
			ctx: &PutRequestContext{
				IsChunkedTransfer: false,
			},
			actualSize:       200 * 1024, // 200KB
			expectedStrategy: ReadStrategyStandardLarge,
		},
		{
			name: "large_chunked_file",
			ctx: &PutRequestContext{
				IsChunkedTransfer: true,
			},
			actualSize:       200 * 1024, // 200KB
			expectedStrategy: ReadStrategyChunkedLarge,
		},
		{
			name: "iceberg_metadata_special_case",
			ctx: &PutRequestContext{
				IsChunkedTransfer: false,
				IsIcebergMeta:     true,
			},
			actualSize:       500 * 1024, // 500KB - would normally be large, but Iceberg meta gets small treatment
			expectedStrategy: ReadStrategyStandardSmall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := determineReadStrategy(tt.ctx, tt.actualSize)
			if strategy != tt.expectedStrategy {
				t.Errorf("determineReadStrategy() = %v, want %v", strategy, tt.expectedStrategy)
			}
		})
	}
}

func TestShouldUseSmallFileOptimization(t *testing.T) {
	tests := []struct {
		name       string
		ctx        *PutRequestContext
		actualSize int64
		expected   bool
	}{
		{
			name:       "small_regular_file",
			ctx:        &PutRequestContext{},
			actualSize: 50 * 1024, // 50KB
			expected:   true,
		},
		{
			name:       "large_regular_file",
			ctx:        &PutRequestContext{},
			actualSize: 200 * 1024, // 200KB
			expected:   false,
		},
		{
			name: "large_iceberg_metadata",
			ctx: &PutRequestContext{
				IsIcebergMeta: true,
			},
			actualSize: 500 * 1024, // 500KB
			expected:   true,
		},
		{
			name: "very_large_iceberg_metadata",
			ctx: &PutRequestContext{
				IsIcebergMeta: true,
			},
			actualSize: 2 * 1024 * 1024, // 2MB
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldUseSmallFileOptimization(tt.ctx, tt.actualSize)
			if result != tt.expected {
				t.Errorf("shouldUseSmallFileOptimization() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestReadStrategyString(t *testing.T) {
	tests := []struct {
		strategy ReadStrategy
		expected string
	}{
		{ReadStrategyStandardSmall, "standard_small"},
		{ReadStrategyChunkedSmall, "chunked_small"},
		{ReadStrategyStandardLarge, "standard_large"},
		{ReadStrategyChunkedLarge, "chunked_large"},
		{ReadStrategy(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.strategy.String()
			if result != tt.expected {
				t.Errorf("ReadStrategy.String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSanitizeETag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid simple etag with quotes",
			input:    `"d41d8cd98f00b204e9800998ecf8427e"`,
			expected: "d41d8cd98f00b204e9800998ecf8427e",
			wantErr:  false,
		},
		{
			name:     "valid simple etag without quotes",
			input:    "d41d8cd98f00b204e9800998ecf8427e",
			expected: "d41d8cd98f00b204e9800998ecf8427e",
			wantErr:  false,
		},
		{
			name:     "valid multipart etag",
			input:    `"abc123def456-5"`,
			expected: "abc123def456-5",
			wantErr:  false,
		},
		{
			name:     "valid multipart etag without quotes",
			input:    "abc123def456-5",
			expected: "abc123def456-5",
			wantErr:  false,
		},
		{
			name:    "invalid characters in etag - character M",
			input:   `"M41d8cd98f00b204e9800998ecf8427e"`,
			wantErr: true,
		},
		{
			name:    "invalid multipart etag format",
			input:   `"abc123-def-456"`,
			wantErr: true,
		},
		{
			name:    "empty etag",
			input:   "",
			wantErr: true,
		},
		{
			name:    "etag with invalid hex characters xyz",
			input:   `"xyz123def456"`,
			wantErr: true,
		},
		{
			name:    "multipart etag with invalid part count",
			input:   `"abc123def456-xyz"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeETag(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("sanitizeETag() expected error but got none for input %q", tt.input)
				}
				return
			}
			
			if err != nil {
				t.Errorf("sanitizeETag() unexpected error: %v", err)
				return
			}
			
			if result != tt.expected {
				t.Errorf("sanitizeETag() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsValidHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid lowercase hex",
			input:    "d41d8cd98f00b204e9800998ecf8427e",
			expected: true,
		},
		{
			name:     "valid uppercase hex",
			input:    "D41D8CD98F00B204E9800998ECF8427E",
			expected: true,
		},
		{
			name:     "valid mixed case hex",
			input:    "D41d8Cd98F00b204E9800998eCf8427E",
			expected: true,
		},
		{
			name:     "invalid character M",
			input:    "M41d8cd98f00b204e9800998ecf8427e",
			expected: false,
		},
		{
			name:     "invalid character xyz",
			input:    "xyz123",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "only numbers",
			input:    "1234567890",
			expected: true,
		},
		{
			name:     "only letters",
			input:    "abcdef",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHex(tt.input)
			if result != tt.expected {
				t.Errorf("isValidHex(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDecodeETagForHashing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid simple etag",
			input:   `"d41d8cd98f00b204e9800998ecf8427e"`,
			wantErr: false,
		},
		{
			name:    "valid multipart etag",
			input:   `"abc123def456-5"`,
			wantErr: false,
		},
		{
			name:    "invalid hex characters",
			input:   `"M41d8cd98f00b204e9800998ecf8427e"`,
			wantErr: true,
		},
		{
			name:    "empty etag",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeETagForHashing(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("decodeETagForHashing() expected error but got none for input %q", tt.input)
				}
				return
			}
			
			if err != nil {
				t.Errorf("decodeETagForHashing() unexpected error: %v", err)
			}
		})
	}
}