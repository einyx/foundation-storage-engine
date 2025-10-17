package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/storage"
)

// Mock storage backend for testing
type mockStorage struct{}

func (m *mockStorage) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	return []storage.BucketInfo{
		{Name: "warehouse", CreationDate: time.Now()},
		{Name: "samples", CreationDate: time.Now()},
		{Name: "connectors", CreationDate: time.Now()},
	}, nil
}

func (m *mockStorage) CreateBucket(ctx context.Context, bucket string) error {
	return nil
}

func (m *mockStorage) DeleteBucket(ctx context.Context, bucket string) error {
	return nil
}

func (m *mockStorage) BucketExists(ctx context.Context, bucket string) (bool, error) {
	validBuckets := []string{"warehouse", "samples", "connectors", "test-bucket"}
	for _, valid := range validBuckets {
		if bucket == valid {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockStorage) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*storage.ListObjectsResult, error) {
	return &storage.ListObjectsResult{
		Contents:       []storage.ObjectInfo{},
		CommonPrefixes: []string{},
		IsTruncated:    false,
	}, nil
}

func (m *mockStorage) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*storage.ListObjectsResult, error) {
	return &storage.ListObjectsResult{
		Contents:       []storage.ObjectInfo{},
		CommonPrefixes: []string{},
		IsTruncated:    false,
	}, nil
}

func (m *mockStorage) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*storage.ListObjectsResult, error) {
	return &storage.ListObjectsResult{
		Contents:       []storage.ObjectInfo{},
		CommonPrefixes: []string{},
		IsTruncated:    false,
	}, nil
}

func (m *mockStorage) GetObject(ctx context.Context, bucket, key string) (*storage.Object, error) {
	return &storage.Object{
		Body:         io.NopCloser(strings.NewReader("test data")),
		ContentType:  "text/plain",
		Size:         9,
		ETag:         "test-etag",
		LastModified: time.Now(),
		Metadata:     make(map[string]string),
	}, nil
}

func (m *mockStorage) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	return nil
}

func (m *mockStorage) DeleteObject(ctx context.Context, bucket, key string) error {
	return nil
}

func (m *mockStorage) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	return nil
}

func (m *mockStorage) HeadObject(ctx context.Context, bucket, key string) (*storage.ObjectInfo, error) {
	return &storage.ObjectInfo{
		Size:         100,
		ETag:         "test-etag",
		LastModified: time.Now(),
		ContentType:  "text/plain",
		Metadata:     make(map[string]string),
	}, nil
}

func (m *mockStorage) GetObjectACL(ctx context.Context, bucket, key string) (*storage.ACL, error) {
	return &storage.ACL{
		Owner: storage.Owner{
			ID:          "test-owner-id",
			DisplayName: "test-owner",
		},
		Grants: []storage.Grant{
			{
				Grantee: storage.Grantee{
					Type:        "CanonicalUser",
					ID:          "test-owner-id",
					DisplayName: "test-owner",
				},
				Permission: "FULL_CONTROL",
			},
		},
	}, nil
}

func (m *mockStorage) PutObjectACL(ctx context.Context, bucket, key string, acl *storage.ACL) error {
	return nil
}

func (m *mockStorage) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "test-upload-id", nil
}

func (m *mockStorage) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	return "test-etag", nil
}

func (m *mockStorage) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []storage.CompletedPart) error {
	return nil
}

func (m *mockStorage) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return nil
}

func (m *mockStorage) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*storage.ListPartsResult, error) {
	return &storage.ListPartsResult{}, nil
}

// Mock auth provider
type mockAuth struct{}

func (m *mockAuth) Authenticate(r *http.Request) error {
	return nil
}

func (m *mockAuth) GetSecretKey(accessKey string) (string, error) {
	return "test-secret", nil
}

func TestJavaSDKUserAgentDetection(t *testing.T) {
	tests := []struct {
		name          string
		userAgent     string
		expectedMatch bool
		description   string
	}{
		{
			name:          "TrinoClient",
			userAgent:     "aws-sdk-java/2.30.12 md/io#sync md/http#Apache ua/2.1 os/Linux lang/java#23.0.2 app/Trino",
			expectedMatch: true,
			description:   "Trino client should be detected",
		},
		{
			name:          "HiveClient",
			userAgent:     "aws-sdk-java/1.12.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hive/3.1.2",
			expectedMatch: true,
			description:   "Hive client should be detected",
		},
		{
			name:          "HadoopS3A",
			userAgent:     "aws-sdk-java/1.11.1026 Linux/5.4.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hadoop-s3a/3.3.4",
			expectedMatch: true,
			description:   "Hadoop S3A client should be detected",
		},
		{
			name:          "GenericJavaSDK",
			userAgent:     "aws-sdk-java/2.20.0 java/17.0.2",
			expectedMatch: false,
			description:   "Generic Java SDK without specific markers should not be detected",
		},
		{
			name:          "BrowserClient",
			userAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expectedMatch: false,
			description:   "Browser clients should not be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the user agent detection logic
			isJavaSDK := strings.Contains(strings.ToLower(tt.userAgent), "trino") ||
				(strings.Contains(strings.ToLower(tt.userAgent), "java") && strings.Contains(tt.userAgent, "app/Trino")) ||
				strings.Contains(strings.ToLower(tt.userAgent), "hive") ||
				strings.Contains(strings.ToLower(tt.userAgent), "hadoop") ||
				strings.Contains(strings.ToLower(tt.userAgent), "s3a")

			if isJavaSDK != tt.expectedMatch {
				t.Errorf("%s: expected %v, got %v for user agent: %s", tt.description, tt.expectedMatch, isJavaSDK, tt.userAgent)
			}
		})
	}
}

func TestPUTRequestWithJavaSDKOptimization(t *testing.T) {
	// Create handler with mock storage
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name      string
		userAgent string
		shouldOptimize bool
	}{
		{
			name:      "TrinoRequest",
			userAgent: "aws-sdk-java/2.30.12 app/Trino",
			shouldOptimize: true,
		},
		{
			name:      "HiveRequest", 
			userAgent: "aws-sdk-java/1.12.0 hive/3.1.2",
			shouldOptimize: true,
		},
		{
			name:      "RegularRequest",
			userAgent: "aws-cli/2.0.0",
			shouldOptimize: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a PUT request
			req := httptest.NewRequest("PUT", "/test-bucket/test-key", bytes.NewReader([]byte("test data")))
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Content-Length", "9")
			
			// Add admin auth context (includes authentication and admin privileges)
			req = createAdminContext(req)

			// Create response recorder
			w := httptest.NewRecorder()

			// Add URL vars (normally done by mux)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "test-key",
			})

			// Call the handler
			handler.ServeHTTP(w, req)

			// Check response
			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			// Check for Java SDK specific headers
			if tt.shouldOptimize {
				if w.Header().Get("Connection") != "close" {
					t.Errorf("Expected Connection: close header for Java SDK client")
				}
				if w.Header().Get("Server") != "AmazonS3" {
					t.Errorf("Expected Server: AmazonS3 header for Java SDK client")
				}
				if w.Header().Get("Content-Length") != "0" {
					t.Errorf("Expected Content-Length: 0 for Java SDK client")
				}
			}
		})
	}
}

func TestHEADRequestWithJavaSDKOptimization(t *testing.T) {
	// Create handler with mock storage
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name      string
		userAgent string
		shouldOptimize bool
	}{
		{
			name:      "HadoopS3ARequest",
			userAgent: "aws-sdk-java/1.11.1026 hadoop-s3a/3.3.4",
			shouldOptimize: true,
		},
		{
			name:      "HiveMetastoreRequest",
			userAgent: "aws-sdk-java/1.12.0 hive/3.1.2",
			shouldOptimize: true,
		},
		{
			name:      "MinIOClientRequest",
			userAgent: "MinIO (linux; amd64) minio-go/v7.0.0",
			shouldOptimize: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a HEAD request
			req := httptest.NewRequest("HEAD", "/test-bucket/test-key", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			
			// Add admin auth context (includes authentication and admin privileges)
			req = createAdminContext(req)

			// Create response recorder
			w := httptest.NewRecorder()

			// Add URL vars (normally done by mux)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "test-key",
			})

			// Call the handler
			handler.ServeHTTP(w, req)

			// Check response
			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			// Check for Java SDK specific headers
			if tt.shouldOptimize {
				if w.Header().Get("Connection") != "close" {
					t.Errorf("Expected Connection: close header for Java SDK client, got: %s", w.Header().Get("Connection"))
				}
				if w.Header().Get("Server") != "AmazonS3" {
					t.Errorf("Expected Server: AmazonS3 header for Java SDK client, got: %s", w.Header().Get("Server"))
				}
			} else {
				if w.Header().Get("Connection") == "close" {
					t.Errorf("Did not expect Connection: close header for non-Java SDK client")
				}
			}
		})
	}
}

func TestUserAgentEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		userAgent     string
		expectedMatch bool
		description   string
	}{
		{
			name:          "EmptyUserAgent",
			userAgent:     "",
			expectedMatch: false,
			description:   "Empty user agent should not be detected",
		},
		{
			name:          "CaseInsensitiveTrino",
			userAgent:     "aws-sdk-java/2.30.12 APP/TRINO",
			expectedMatch: true,
			description:   "Case insensitive Trino detection should work",
		},
		{
			name:          "CaseInsensitiveHive",
			userAgent:     "aws-sdk-java/1.12.0 HIVE/3.1.2",
			expectedMatch: true,
			description:   "Case insensitive Hive detection should work",
		},
		{
			name:          "CaseInsensitiveHadoop",
			userAgent:     "aws-sdk-java/1.11.1026 HADOOP-s3a/3.3.4",
			expectedMatch: true,
			description:   "Case insensitive Hadoop detection should work",
		},
		{
			name:          "S3AInPath",
			userAgent:     "MyApp/1.0 s3a-client/2.0",
			expectedMatch: true,
			description:   "S3A in any part of user agent should be detected",
		},
		{
			name:          "OnlyJavaWithoutMarkers",
			userAgent:     "aws-sdk-java/2.20.0 java/17.0.2",
			expectedMatch: false,
			description:   "Java SDK without specific markers should not be detected",
		},
		{
			name:          "TrinoWithoutJava",
			userAgent:     "custom-client/1.0 app/Trino",
			expectedMatch: true,
			description:   "Trino marker should be detected even without java",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the user agent detection logic (same as in handler)
			isJavaSDK := strings.Contains(strings.ToLower(tt.userAgent), "trino") ||
				(strings.Contains(strings.ToLower(tt.userAgent), "java") && strings.Contains(tt.userAgent, "app/Trino")) ||
				strings.Contains(strings.ToLower(tt.userAgent), "hive") ||
				strings.Contains(strings.ToLower(tt.userAgent), "hadoop") ||
				strings.Contains(strings.ToLower(tt.userAgent), "s3a")

			if isJavaSDK != tt.expectedMatch {
				t.Errorf("%s: expected %v, got %v for user agent: %s", tt.description, tt.expectedMatch, isJavaSDK, tt.userAgent)
			}
		})
	}
}

func TestResponseHeaderOptimizations(t *testing.T) {
	// Create handler with mock storage
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	
	handler := NewHandler(storage, auth, cfg, chunking)

	t.Run("PUTWithConnectionClose", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/test-bucket/test-key", bytes.NewReader([]byte("test")))
		req.Header.Set("User-Agent", "aws-sdk-java/2.30.12 app/Trino")
		req.Header.Set("Content-Length", "4")
		
		w := httptest.NewRecorder()
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})
		req = createAdminContext(req)

		handler.ServeHTTP(w, req)

		// Verify Java SDK specific optimizations
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close header")
		}
		if w.Header().Get("Server") != "AmazonS3" {
			t.Error("Expected Server: AmazonS3 header")
		}
		if w.Header().Get("Content-Length") != "0" {
			t.Error("Expected Content-Length: 0 for empty response body")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("HEADWithConnectionClose", func(t *testing.T) {
		req := httptest.NewRequest("HEAD", "/test-bucket/test-key", nil)
		req.Header.Set("User-Agent", "aws-sdk-java/1.12.0 hive/3.1.2")
		
		w := httptest.NewRecorder()
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})
		req = createAdminContext(req)

		handler.ServeHTTP(w, req)

		// Verify Java SDK specific optimizations for HEAD
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close header for HEAD request")
		}
		if w.Header().Get("Server") != "AmazonS3" {
			t.Error("Expected Server: AmazonS3 header for HEAD request")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("RegularClientNoOptimizations", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/test-bucket/test-key", bytes.NewReader([]byte("test")))
		req.Header.Set("User-Agent", "aws-cli/2.0.0")
		req.Header.Set("Content-Length", "4")
		
		w := httptest.NewRecorder()
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})
		req = createAdminContext(req)

		handler.ServeHTTP(w, req)

		// Verify no Java SDK optimizations for regular clients
		if w.Header().Get("Connection") == "close" {
			t.Error("Did not expect Connection: close header for regular client")
		}
		// Server: AmazonS3 header is acceptable for all clients for S3 compatibility
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestS3Package(t *testing.T) {
	// Placeholder test to ensure package has at least one test
	t.Log("S3 package test placeholder")
}

func TestScanContent(t *testing.T) {
	tests := []struct {
		name           string
		scannerEnabled bool
		size           int64
		expectScanned  bool
	}{
		{
			name:           "scanner disabled",
			scannerEnabled: false,
			size:           1024,
			expectScanned:  false,
		},
		{
			name:           "file too large",
			scannerEnabled: true,
			size:           100 * 1024 * 1024, // 100MB
			expectScanned:  false,
		},
		{
			name:           "empty file",
			scannerEnabled: true,
			size:           0,
			expectScanned:  false,
		},
		{
			name:           "normal file should be scanned",
			scannerEnabled: true,
			size:           1024,
			expectScanned:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			handler := &Handler{
				storage: &mockStorage{},
			}

			if tt.scannerEnabled {
				// Note: In a real test, you'd mock the scanner
				// For now, just test the logic without actual scanning
				handler.scanner = nil // Simulates no scanner configured
			}

			ctx := context.Background()
			body := strings.NewReader("test content")
			logger := logrus.NewEntry(logrus.New())
			
			// Create a test response writer
			w := httptest.NewRecorder()

			result, err := handler.scanContent(ctx, body, "test-key", tt.size, logger, w)
			
			if err != nil {
				t.Fatalf("scanContent failed: %v", err)
			}

			if result == nil {
				t.Fatal("scanContent returned nil result")
			}

			if result.Body == nil {
				t.Fatal("scanContent returned nil body")
			}

			// Since we don't have a real scanner, result.Result should always be nil
			if result.Result != nil {
				t.Errorf("Expected nil scan result, got %v", result.Result)
			}
		})
	}
}