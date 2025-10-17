package s3

import (
	"net/http/httptest"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

func TestHandleSDKv2Request(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	tests := []struct {
		name        string
		userAgent   string
		path        string
		shouldProxy bool
		description string
	}{
		{
			name:        "Trino SDK request",
			userAgent:   "aws-sdk-java/2.30.12 md/io#sync md/http#Apache ua/2.1 os/Linux lang/java#23.0.2 app/Trino",
			path:        "/warehouse/data.parquet",
			shouldProxy: true,
			description: "Trino requests should be proxied",
		},
		{
			name:        "Hive SDK request",
			userAgent:   "aws-sdk-java/1.12.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hive/3.1.2",
			path:        "/warehouse/data.parquet",
			shouldProxy: true,
			description: "Hive requests should be proxied",
		},
		{
			name:        "Generic Java SDK",
			userAgent:   "aws-sdk-java/2.20.0",
			path:        "/warehouse/data.parquet",
			shouldProxy: true,
			description: "Generic Java SDK requests should be proxied",
		},
		{
			name:        "Python boto3",
			userAgent:   "aws-cli/2.0.0 Python/3.8.0",
			path:        "/warehouse/data.parquet",
			shouldProxy: false,
			description: "Non-Java SDK requests should not be proxied",
		},
		{
			name:        "Browser request",
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			path:        "/warehouse/data.parquet",
			shouldProxy: false,
			description: "Browser requests should not be proxied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			req.Header.Set("User-Agent", tt.userAgent)
			rr := httptest.NewRecorder()

			result := handler.handleSDKv2Request(rr, req)

			if tt.shouldProxy && !result {
				t.Errorf("%s: Expected handleSDKv2Request to return true for Java SDK", tt.description)
			}
			if !tt.shouldProxy && result {
				t.Errorf("%s: Expected handleSDKv2Request to return false for non-Java SDK", tt.description)
			}
		})
	}
}

func TestHandleSDKv2RequestErrorHandling(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("GET", "/nonexistent/file.txt", nil)
	req.Header.Set("User-Agent", "aws-sdk-java/2.30.12 app/Trino")
	rr := httptest.NewRecorder()

	result := handler.handleSDKv2Request(rr, req)

	// Should detect Java SDK and return true
	if !result {
		t.Error("handleSDKv2Request should return true for Trino client")
	}
}

func TestHandleSDKv2RequestWithRange(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("GET", "/warehouse/data.parquet", nil)
	req.Header.Set("User-Agent", "aws-sdk-java/2.30.12 app/Trino")
	req.Header.Set("Range", "bytes=0-1023")
	rr := httptest.NewRecorder()

	result := handler.handleSDKv2Request(rr, req)

	// Should detect Java SDK and return true
	if !result {
		t.Error("handleSDKv2Request should return true for Trino client with range header")
	}
}
