package s3

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/mux"
)

const testUploadID = "test-upload-id-123456"

func TestInitiateMultipartUpload(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("POST", "/warehouse/testfile.txt?uploads", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	rr := httptest.NewRecorder()

	handler.initiateMultipartUpload(rr, req, "warehouse", "testfile.txt")

	if rr.Code != http.StatusOK {
		t.Errorf("initiateMultipartUpload() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result struct {
		UploadId string `xml:"UploadId"`
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
	}

	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if result.UploadId != testUploadID {
		t.Errorf("Expected upload ID '%s', got '%s'", testUploadID, result.UploadId)
	}
	if result.Bucket != "warehouse" {
		t.Errorf("Expected bucket 'warehouse', got '%s'", result.Bucket)
	}
	if result.Key != "testfile.txt" {
		t.Errorf("Expected key 'testfile.txt', got '%s'", result.Key)
	}
}

func TestUploadPart(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	body := strings.NewReader("test part data")
	req := httptest.NewRequest("PUT", "/warehouse/testfile.txt?partNumber=1&uploadId="+testUploadID, body)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	req.Header.Set("Content-Length", "14")
	rr := httptest.NewRecorder()

	handler.uploadPart(rr, req, "warehouse", "testfile.txt", testUploadID, "1")

	if rr.Code != http.StatusOK {
		t.Errorf("uploadPart() status = %d, want %d", rr.Code, http.StatusOK)
	}

	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Error("uploadPart() should return ETag header")
	}
}

func TestCompleteMultipartUpload(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	completeReq := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	body := strings.NewReader(completeReq)
	req := httptest.NewRequest("POST", "/warehouse/testfile.txt?uploadId="+testUploadID, body)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	req.Header.Set("Content-Type", "application/xml")
	rr := httptest.NewRecorder()

	handler.completeMultipartUpload(rr, req, "warehouse", "testfile.txt", testUploadID)

	if rr.Code != http.StatusOK {
		t.Errorf("completeMultipartUpload() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result struct {
		Location string `xml:"Location"`
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
		ETag     string `xml:"ETag"`
	}

	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if result.Bucket != "warehouse" {
		t.Errorf("Expected bucket 'warehouse', got '%s'", result.Bucket)
	}
	if result.Key != "testfile.txt" {
		t.Errorf("Expected key 'testfile.txt', got '%s'", result.Key)
	}
}

func TestAbortMultipartUpload(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("DELETE", "/warehouse/testfile.txt?uploadId="+testUploadID, nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	rr := httptest.NewRecorder()

	handler.abortMultipartUpload(rr, req, "warehouse", "testfile.txt", testUploadID)

	if rr.Code != http.StatusNoContent {
		t.Errorf("abortMultipartUpload() status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestListParts(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("GET", "/warehouse/testfile.txt?uploadId="+testUploadID, nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	rr := httptest.NewRecorder()

	handler.listParts(rr, req, "warehouse", "testfile.txt", testUploadID)

	if rr.Code != http.StatusOK {
		t.Errorf("listParts() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result struct {
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
		UploadId string `xml:"UploadId"`
	}

	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if result.Bucket != "warehouse" {
		t.Errorf("Expected bucket 'warehouse', got '%s'", result.Bucket)
	}
	if result.Key != "testfile.txt" {
		t.Errorf("Expected key 'testfile.txt', got '%s'", result.Key)
	}
	if result.UploadId != testUploadID {
		t.Errorf("Expected upload ID '%s', got '%s'", testUploadID, result.UploadId)
	}
}
