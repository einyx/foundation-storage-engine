package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/storage"
	"github.com/gorilla/mux"
)

// Mock storage with error simulation capabilities
type errorMockStorage struct {
	*mockStorage
	simulateErrors map[string]error
}

func newErrorMockStorage() *errorMockStorage {
	return &errorMockStorage{
		mockStorage:    &mockStorage{},
		simulateErrors: make(map[string]error),
	}
}

func (m *errorMockStorage) SimulateError(operation string, err error) {
	m.simulateErrors[operation] = err
}

func (m *errorMockStorage) GetObject(ctx context.Context, bucket, key string) (*storage.Object, error) {
	if err, exists := m.simulateErrors["GetObject"]; exists {
		return nil, err
	}
	return m.mockStorage.GetObject(ctx, bucket, key)
}

func (m *errorMockStorage) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	if err, exists := m.simulateErrors["PutObject"]; exists {
		return err
	}
	return m.mockStorage.PutObject(ctx, bucket, key, reader, size, metadata)
}

func (m *errorMockStorage) DeleteObject(ctx context.Context, bucket, key string) error {
	if err, exists := m.simulateErrors["DeleteObject"]; exists {
		return err
	}
	return m.mockStorage.DeleteObject(ctx, bucket, key)
}

func (m *errorMockStorage) HeadObject(ctx context.Context, bucket, key string) (*storage.ObjectInfo, error) {
	if err, exists := m.simulateErrors["HeadObject"]; exists {
		return nil, err
	}
	return m.mockStorage.HeadObject(ctx, bucket, key)
}

func (m *errorMockStorage) BucketExists(ctx context.Context, bucket string) (bool, error) {
	if err, exists := m.simulateErrors["BucketExists"]; exists {
		return false, err
	}
	return m.mockStorage.BucketExists(ctx, bucket)
}

func (m *errorMockStorage) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	if err, exists := m.simulateErrors["ListBuckets"]; exists {
		return nil, err
	}
	return m.mockStorage.ListBuckets(ctx)
}

func TestGetObjectErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		simulateError  error
		expectedStatus int
		expectedInBody string
	}{
		{
			name:           "object not found",
			simulateError:  errors.New("object not found"),
			expectedStatus: http.StatusNotFound,
			expectedInBody: "object not found",
		},
		{
			name:           "storage backend error",
			simulateError:  errors.New("storage backend unavailable"),
			expectedStatus: http.StatusNotFound,
			expectedInBody: "storage backend unavailable",
		},
		{
			name:           "permission denied",
			simulateError:  errors.New("access denied"),
			expectedStatus: http.StatusNotFound,
			expectedInBody: "access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := newErrorMockStorage()
			storage.SimulateError("GetObject", tt.simulateError)

			auth := &mockAuth{}
			cfg := config.S3Config{}
			chunking := config.ChunkingConfig{}
			handler := NewHandler(storage, auth, cfg, chunking)

			req := httptest.NewRequest("GET", "/test-bucket/nonexistent.txt", nil)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "nonexistent.txt",
			})

			w := httptest.NewRecorder()
			handler.handleObject(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if !strings.Contains(w.Body.String(), tt.expectedInBody) {
				t.Errorf("Expected body to contain %q, got %q", tt.expectedInBody, w.Body.String())
			}

			// Should return XML error format
			if !strings.Contains(w.Header().Get("Content-Type"), "xml") {
				t.Error("Expected XML content type for error response")
			}
		})
	}
}

func TestPutObjectErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		simulateError  error
		expectedStatus int
	}{
		{
			name:           "storage write error",
			simulateError:  errors.New("disk full"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "permission error",
			simulateError:  errors.New("write permission denied"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "network error",
			simulateError:  errors.New("network timeout"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := newErrorMockStorage()
			storage.SimulateError("PutObject", tt.simulateError)

			auth := &mockAuth{}
			cfg := config.S3Config{}
			chunking := config.ChunkingConfig{}
			handler := NewHandler(storage, auth, cfg, chunking)

			req := httptest.NewRequest("PUT", "/test-bucket/test.txt",
				strings.NewReader("test data"))
			req.Header.Set("Content-Length", "9")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "test.txt",
			})

			w := httptest.NewRecorder()
			handler.handleObject(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestHeadObjectErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		simulateError  error
		expectedStatus int
	}{
		{
			name:           "object not found",
			simulateError:  errors.New("object not found"),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "storage backend error",
			simulateError:  errors.New("backend unavailable"),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := newErrorMockStorage()
			storage.SimulateError("HeadObject", tt.simulateError)

			auth := &mockAuth{}
			cfg := config.S3Config{}
			chunking := config.ChunkingConfig{}
			handler := NewHandler(storage, auth, cfg, chunking)

			req := httptest.NewRequest("HEAD", "/test-bucket/nonexistent.txt", nil)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "nonexistent.txt",
			})

			w := httptest.NewRecorder()
			handler.handleObject(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestDeleteObjectErrorHandling(t *testing.T) {
	storage := newErrorMockStorage()
	storage.SimulateError("DeleteObject", errors.New("delete failed"))

	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	req := httptest.NewRequest("DELETE", "/test-bucket/test.txt", nil)
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestListBucketsErrorHandling(t *testing.T) {
	storage := newErrorMockStorage()
	storage.SimulateError("ListBuckets", errors.New("backend unavailable"))

	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	req := httptest.NewRequest("GET", "/", nil)
	req = createAdminContext(req)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestInvalidBucketNameHandling(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name       string
		bucketName string
	}{
		{
			name:       "bucket name too short",
			bucketName: "ab",
		},
		{
			name:       "bucket name with dots",
			bucketName: "bucket..name",
		},
		{
			name:       "empty bucket name",
			bucketName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", fmt.Sprintf("/%s/object.txt", tt.bucketName), nil)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": tt.bucketName,
				"key":    "object.txt",
			})

			w := httptest.NewRecorder()
			handler.handleObject(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 for invalid bucket name %q, got %d", tt.bucketName, w.Code)
			}
		})
	}
}

func TestInvalidObjectKeyHandling(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name string
		key  string
	}{
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "key with double dots",
			key:  "../secret.txt",
		},
		{
			name: "key with backslash",
			key:  "folder\\file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test-bucket/"+tt.key, nil)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    tt.key,
			})

			w := httptest.NewRecorder()
			handler.handleObject(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 for invalid key %q, got %d", tt.key, w.Code)
			}
		})
	}
}

func TestMissingContentLengthHandling(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	req := httptest.NewRequest("PUT", "/test-bucket/test.txt",
		strings.NewReader("test data"))
	// Don't set Content-Length header
	req.ContentLength = -1
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing Content-Length, got %d", w.Code)
	}
}

func TestUnsupportedMethodHandling(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Test unsupported method on object
	req := httptest.NewRequest("PATCH", "/test-bucket/test.txt", nil)
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 for unsupported method, got %d", w.Code)
	}
}

func TestPanicRecoveryInHandlers(t *testing.T) {
	// Test that panic recovery works in object handlers
	storage := &panicMockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "GET object panic recovery",
			method: "GET",
			path:   "/test-bucket/panic.txt",
		},
		{
			name:   "PUT object panic recovery",
			method: "PUT",
			path:   "/test-bucket/panic.txt",
		},
		{
			name:   "HEAD object panic recovery",
			method: "HEAD",
			path:   "/test-bucket/panic.txt",
		},
		{
			name:   "DELETE object panic recovery",
			method: "DELETE",
			path:   "/test-bucket/panic.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.method == "PUT" {
				body = strings.NewReader("test data")
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.method == "PUT" {
				req.Header.Set("Content-Length", "9")
			}
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "panic.txt",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// Should recover from panic and return 500
			if w.Code != http.StatusInternalServerError {
				t.Errorf("Expected status 500 after panic recovery, got %d", w.Code)
			}
		})
	}
}

// Mock storage that panics on operations
type panicMockStorage struct{}

func (m *panicMockStorage) GetObject(ctx context.Context, bucket, key string) (*storage.Object, error) {
	panic("simulated panic in GetObject")
}

func (m *panicMockStorage) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	panic("simulated panic in PutObject")
}

func (m *panicMockStorage) HeadObject(ctx context.Context, bucket, key string) (*storage.ObjectInfo, error) {
	panic("simulated panic in HeadObject")
}

func (m *panicMockStorage) DeleteObject(ctx context.Context, bucket, key string) error {
	panic("simulated panic in DeleteObject")
}

// Implement other required methods with no-ops
func (m *panicMockStorage) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	return nil, nil
}

func (m *panicMockStorage) CreateBucket(ctx context.Context, bucket string) error {
	return nil
}

func (m *panicMockStorage) DeleteBucket(ctx context.Context, bucket string) error {
	return nil
}

func (m *panicMockStorage) BucketExists(ctx context.Context, bucket string) (bool, error) {
	return true, nil
}

func (m *panicMockStorage) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*storage.ListObjectsResult, error) {
	return nil, nil
}

func (m *panicMockStorage) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*storage.ListObjectsResult, error) {
	return nil, nil
}

func (m *panicMockStorage) ListDeletedObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*storage.ListObjectsResult, error) {
	return nil, nil
}

func (m *panicMockStorage) RestoreObject(ctx context.Context, bucket, key, versionID string) error {
	return nil
}

func (m *panicMockStorage) GetObjectACL(ctx context.Context, bucket, key string) (*storage.ACL, error) {
	return nil, nil
}

func (m *panicMockStorage) PutObjectACL(ctx context.Context, bucket, key string, acl *storage.ACL) error {
	return nil
}

func (m *panicMockStorage) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "", nil
}

func (m *panicMockStorage) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	return "", nil
}

func (m *panicMockStorage) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []storage.CompletedPart) error {
	return nil
}

func (m *panicMockStorage) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return nil
}

func (m *panicMockStorage) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*storage.ListPartsResult, error) {
	return nil, nil
}

func TestInvalidMultipartUploadID(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	req := httptest.NewRequest("PUT", "/test-bucket/test.txt?uploadId=invalid&partNumber=1",
		strings.NewReader("test"))
	req.Header.Set("Content-Length", "4")
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid upload ID, got %d", w.Code)
	}
}

func TestInvalidPartNumber(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	req := httptest.NewRequest("PUT", "/test-bucket/test.txt?uploadId=valid-upload-id&partNumber=0",
		strings.NewReader("test"))
	req.Header.Set("Content-Length", "4")
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid part number, got %d", w.Code)
	}
}

func TestClientDisconnectDuringUpload(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Create a reader that simulates client disconnect
	disconnectReader := &clientDisconnectReader{
		data: []byte("some data before disconnect"),
		pos:  0,
	}

	req := httptest.NewRequest("PUT", "/test-bucket/test.txt", disconnectReader)
	req.Header.Set("Content-Length", "1000") // Claim more data than available
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should handle the error gracefully
	if w.Code == http.StatusOK {
		t.Error("Expected error status for client disconnect, got 200")
	}
}

// Reader that simulates client disconnect
type clientDisconnectReader struct {
	data []byte
	pos  int
}

func (r *clientDisconnectReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("connection reset by peer")
	}

	n := copy(p, r.data[r.pos:])
	r.pos += n

	if r.pos >= len(r.data) {
		return n, errors.New("connection reset by peer")
	}

	return n, nil
}

func TestResponseWriterAfterWriteStarted(t *testing.T) {
	// Test that we handle cases where response has already been started
	w := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     200,
		written:        false,
	}

	// Write first header
	w.WriteHeader(http.StatusOK)

	// Try to write different status - should not change
	w.WriteHeader(http.StatusInternalServerError)

	if w.statusCode != http.StatusOK {
		t.Errorf("Expected status to remain 200, got %d", w.statusCode)
	}

	if !w.written {
		t.Error("Expected written flag to be true")
	}
}

func TestEmptyFileUpload(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	req := httptest.NewRequest("PUT", "/test-bucket/empty.txt", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Length", "0")
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "empty.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for empty file, got %d", w.Code)
	}

	// Should get empty file ETag
	etag := w.Header().Get("ETag")
	if etag != `"d41d8cd98f00b204e9800998ecf8427e"` {
		t.Errorf("Expected empty file ETag, got %s", etag)
	}
}
