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

func TestGetObjectACL(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	req := httptest.NewRequest("GET", "/warehouse/testfile.txt?acl", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	rr := httptest.NewRecorder()

	handler.getObjectACL(rr, req, "warehouse", "testfile.txt")

	if rr.Code != http.StatusOK {
		t.Errorf("getObjectACL() status = %d, want %d", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/xml" {
		t.Errorf("Expected Content-Type 'application/xml', got '%s'", contentType)
	}

	var result struct {
		Owner struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
	}

	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("Failed to unmarshal ACL response: %v", err)
	}

	if result.Owner.ID == "" {
		t.Error("getObjectACL() should return owner ID")
	}
}

func TestPutObjectACL(t *testing.T) {
	s3cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}

	handler := NewHandler(&mockStorage{}, &mockAuth{}, s3cfg, chunking)

	aclXML := `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
	<Owner>
		<ID>owner-id</ID>
		<DisplayName>owner-name</DisplayName>
	</Owner>
	<AccessControlList>
		<Grant>
			<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
				<ID>owner-id</ID>
				<DisplayName>owner-name</DisplayName>
			</Grantee>
			<Permission>FULL_CONTROL</Permission>
		</Grant>
	</AccessControlList>
</AccessControlPolicy>`

	body := strings.NewReader(aclXML)
	req := httptest.NewRequest("PUT", "/warehouse/testfile.txt?acl", body)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "testfile.txt",
	})
	req.Header.Set("Content-Type", "application/xml")
	rr := httptest.NewRecorder()

	handler.putObjectACL(rr, req, "warehouse", "testfile.txt")

	if rr.Code != http.StatusOK {
		t.Errorf("putObjectACL() status = %d, want %d", rr.Code, http.StatusOK)
	}
}
