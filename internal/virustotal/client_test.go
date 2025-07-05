package virustotal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanResult(t *testing.T) {
	tests := []struct {
		name           string
		result         ScanResult
		expectedThreat bool
		expectedLevel  string
	}{
		{
			name: "clean file",
			result: ScanResult{
				Malicious:  0,
				Suspicious: 0,
				Harmless:   50,
				TotalScans: 50,
			},
			expectedThreat: false,
			expectedLevel:  "CLEAN (50/50 scans)",
		},
		{
			name: "malicious file",
			result: ScanResult{
				Malicious:  10,
				Suspicious: 0,
				Harmless:   40,
				TotalScans: 50,
			},
			expectedThreat: true,
			expectedLevel:  "MALICIOUS (10/50 detections)",
		},
		{
			name: "suspicious file",
			result: ScanResult{
				Malicious:  0,
				Suspicious: 5,
				Harmless:   45,
				TotalScans: 50,
			},
			expectedThreat: true,
			expectedLevel:  "SUSPICIOUS (5/50 detections)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedThreat, tt.result.IsThreat())
			assert.Equal(t, tt.expectedLevel, tt.result.GetThreatLevel())
		})
	}
}

func TestClientScanFile(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/files":
			// Upload response
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "test-api-key", r.Header.Get("x-apikey"))
			
			response := map[string]interface{}{
				"data": map[string]string{
					"id": "test-analysis-123",
				},
			}
			json.NewEncoder(w).Encode(response)
			
		case "/analyses/test-analysis-123":
			// Analysis status response
			assert.Equal(t, "GET", r.Method)
			
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"attributes": map[string]string{
						"status": "completed",
					},
				},
			}
			json.NewEncoder(w).Encode(response)
			
		case "/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
			// File report response (SHA256 of empty string)
			assert.Equal(t, "GET", r.Method)
			
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"attributes": map[string]interface{}{
						"last_analysis_stats": map[string]int{
							"malicious":  0,
							"suspicious": 0,
							"undetected": 10,
							"harmless":   40,
						},
						"last_analysis_date": time.Now().Unix(),
						"sha256":             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						"permalink":          "https://www.virustotal.com/file/test",
					},
				},
			}
			json.NewEncoder(w).Encode(response)
			
		default:
			t.Fatalf("Unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	// Override base URL for testing
	oldBaseURL := baseURL
	baseURL = server.URL
	defer func() { baseURL = oldBaseURL }()

	client := NewClient("test-api-key", 1024)
	
	// Test scanning empty file
	result, err := client.ScanFile(context.Background(), bytes.NewReader([]byte{}), "test.txt", 0)
	require.NoError(t, err)
	require.NotNil(t, result)
	
	assert.Equal(t, "clean", result.Verdict)
	assert.Equal(t, 0, result.Malicious)
	assert.Equal(t, 0, result.Suspicious)
	assert.Equal(t, 40, result.Harmless)
	assert.False(t, result.IsThreat())
}

func TestClientFileSizeLimit(t *testing.T) {
	client := NewClient("test-api-key", 1024)
	
	// Test file too large
	result, err := client.ScanFile(context.Background(), nil, "large.bin", 2048)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	assert.Nil(t, result)
}

func TestClientCheckHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/test-hash-123" {
			if r.Method == "GET" {
				// File not found
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		t.Fatalf("Unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	oldBaseURL := baseURL
	baseURL = server.URL
	defer func() { baseURL = oldBaseURL }()

	client := NewClient("test-api-key", 1024)
	
	// Test checking non-existent hash
	result, err := client.CheckHash(context.Background(), "test-hash-123")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

// Mock reader for testing
type mockReader struct {
	data []byte
	pos  int
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}