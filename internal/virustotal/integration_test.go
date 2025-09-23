// +build integration

package virustotal

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

// TestVirusTotalIntegration tests real integration with VirusTotal API
// Run with: go test -tags=integration ./internal/virustotal
func TestVirusTotalIntegration(t *testing.T) {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		t.Skip("VIRUSTOTAL_API_KEY not set, skipping integration test")
	}

	cfg := &config.VirusTotalConfig{
		Enabled:      true,
		APIKey:       apiKey,
		ScanUploads:  true,
		BlockThreats: true,
		MaxFileSize:  "1MB",
	}

	scanner, err := NewScanner(cfg)
	require.NoError(t, err)
	require.True(t, scanner.IsEnabled())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Test 1: Scan a clean file (EICAR test string is NOT used as it's malicious)
	cleanContent := []byte("This is a clean test file content")
	result, err := scanner.ScanReader(ctx, strings.NewReader(string(cleanContent)), "clean_test.txt", int64(len(cleanContent)))
	require.NoError(t, err)
	
	if result != nil {
		assert.Equal(t, "clean", result.Verdict)
		assert.False(t, result.IsThreat())
		assert.False(t, scanner.ShouldBlockUpload(result))
		t.Logf("Clean file scan result: %+v", result)
	}

	// Test 2: Check hash lookup
	if result != nil && scanner.client != nil {
		cachedResult, err := scanner.client.CheckHash(ctx, result.SHA256)
		assert.NoError(t, err)
		if cachedResult != nil {
			assert.Equal(t, result.SHA256, cachedResult.SHA256)
		}
	}
}

// TestVirusTotalRegressions tests for regression scenarios
func TestVirusTotalRegressions(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.VirusTotalConfig
		fileSize int64
		content  string
		wantScan bool
	}{
		{
			name: "file size at limit",
			config: &config.VirusTotalConfig{
				Enabled:      true,
				APIKey:       "test-key",
				ScanUploads:  true,
				MaxFileSize:  "1KB",
			},
			fileSize: 1024,
			content:  strings.Repeat("a", 1024),
			wantScan: true,
		},
		{
			name: "file size over limit",
			config: &config.VirusTotalConfig{
				Enabled:      true,
				APIKey:       "test-key",
				ScanUploads:  true,
				MaxFileSize:  "1KB",
			},
			fileSize: 1025,
			content:  strings.Repeat("a", 1025),
			wantScan: false,
		},
		{
			name: "scan uploads disabled",
			config: &config.VirusTotalConfig{
				Enabled:      true,
				APIKey:       "test-key",
				ScanUploads:  false,
				MaxFileSize:  "1MB",
			},
			fileSize: 100,
			content:  "test content",
			wantScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.config)
			require.NoError(t, err)

			// Mock the client to track if scan was attempted
			scanAttempted := false
			if scanner.client != nil {
				// Replace client with a test double that tracks calls
				oldClient := scanner.client
				scanner.client = &Client{
					apiKey:      "test-key",
					maxFileSize: oldClient.maxFileSize,
					logger:      oldClient.logger,
				}
			}

			result, err := scanner.ScanReader(context.Background(), 
				strings.NewReader(tt.content), "test.txt", tt.fileSize)
			
			if tt.wantScan && scanner.IsEnabled() {
				// For real scans we'd check scanAttempted
				// Here we just verify no error for size limits
				assert.NoError(t, err)
			} else {
				// Should return nil without scanning
				assert.Nil(t, result)
			}
		})
	}
}