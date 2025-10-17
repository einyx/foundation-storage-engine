package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/mux"
)

func TestHandleCopyObject(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	tests := []struct {
		name           string
		copySource     string
		expectedStatus int
		description    string
	}{
		{
			name:           "valid copy operation",
			copySource:     "samples/source-file.txt",
			expectedStatus: http.StatusOK,
			description:    "Copy from valid source should succeed",
		},
		{
			name:           "invalid source format",
			copySource:     "invalid-source",
			expectedStatus: http.StatusBadRequest,
			description:    "Invalid source format should return bad request",
		},
		{
			name:           "empty copy source",
			copySource:     "",
			expectedStatus: http.StatusBadRequest,
			description:    "Empty copy source should return bad request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/warehouse/destination-file.txt", nil)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "destination-file.txt",
			})
			if tt.copySource != "" {
				req.Header.Set("X-Amz-Copy-Source", tt.copySource)
			}
			rr := httptest.NewRecorder()

			handler.handleCopyObject(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: handleCopyObject() status = %d, want %d", tt.description, rr.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/xml" {
					t.Errorf("Expected Content-Type 'application/xml', got '%s'", contentType)
				}
			}
		})
	}
}

func TestHandleCopyObjectMetadata(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("PUT", "/warehouse/destination-file.txt", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "destination-file.txt",
	})
	req.Header.Set("X-Amz-Copy-Source", "samples/source-file.txt")
	req.Header.Set("X-Amz-Metadata-Directive", "REPLACE")
	req.Header.Set("X-Amz-Meta-Custom", "custom-value")
	rr := httptest.NewRecorder()

	handler.handleCopyObject(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleCopyObject() with metadata status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleCopyObjectSameBucket(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("PUT", "/warehouse/destination-file.txt", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "destination-file.txt",
	})
	req.Header.Set("X-Amz-Copy-Source", "warehouse/source-file.txt")
	rr := httptest.NewRecorder()

	handler.handleCopyObject(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleCopyObject() same bucket status = %d, want %d", rr.Code, http.StatusOK)
	}
}
