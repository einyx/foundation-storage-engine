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

func TestHandleBulkDelete(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	deleteXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Object>
		<Key>file1.txt</Key>
	</Object>
	<Object>
		<Key>file2.txt</Key>
	</Object>
	<Quiet>false</Quiet>
</Delete>`

	body := strings.NewReader(deleteXML)
	req := httptest.NewRequest("POST", "/warehouse?delete", body)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
	})
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Content-MD5", "test-md5")
	rr := httptest.NewRecorder()

	handler.handleBulkDelete(rr, req, "warehouse")

	if rr.Code != http.StatusOK {
		t.Errorf("handleBulkDelete() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result struct {
		Deleted []struct {
			Key string `xml:"Key"`
		} `xml:"Deleted"`
	}

	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("Failed to unmarshal delete response: %v", err)
	}

	if len(result.Deleted) != 2 {
		t.Errorf("Expected 2 deleted objects, got %d", len(result.Deleted))
	}

	expectedKeys := []string{"file1.txt", "file2.txt"}
	for i, deleted := range result.Deleted {
		if deleted.Key != expectedKeys[i] {
			t.Errorf("Expected deleted key '%s', got '%s'", expectedKeys[i], deleted.Key)
		}
	}
}

func TestHandleBulkDeleteWithErrors(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	deleteXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Object>
		<Key>valid-file.txt</Key>
	</Object>
	<Quiet>false</Quiet>
</Delete>`

	body := strings.NewReader(deleteXML)
	req := httptest.NewRequest("POST", "/warehouse?delete", body)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
	})
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Content-MD5", "test-md5")
	rr := httptest.NewRecorder()

	handler.handleBulkDelete(rr, req, "warehouse")

	if rr.Code != http.StatusOK {
		t.Errorf("handleBulkDelete() status = %d, want %d", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/xml" {
		t.Errorf("Expected Content-Type 'application/xml', got '%s'", contentType)
	}
}

func TestHandleBulkDeleteQuietMode(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	deleteXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Object>
		<Key>file1.txt</Key>
	</Object>
	<Quiet>true</Quiet>
</Delete>`

	body := strings.NewReader(deleteXML)
	req := httptest.NewRequest("POST", "/warehouse?delete", body)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
	})
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Content-MD5", "test-md5")
	rr := httptest.NewRecorder()

	handler.handleBulkDelete(rr, req, "warehouse")

	if rr.Code != http.StatusOK {
		t.Errorf("handleBulkDelete() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result struct {
		Deleted []struct {
			Key string `xml:"Key"`
		} `xml:"Deleted"`
	}

	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("Failed to unmarshal delete response: %v", err)
	}

	if len(result.Deleted) > 0 {
		t.Error("In quiet mode, successful deletes should not be returned")
	}
}