package virustotal

import (
	"context"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.VirusTotalConfig
		wantErr bool
		wantEnabled bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
			wantEnabled: false,
		},
		{
			name: "disabled config",
			config: &config.VirusTotalConfig{
				Enabled: false,
			},
			wantErr: false,
			wantEnabled: false,
		},
		{
			name: "enabled without API key",
			config: &config.VirusTotalConfig{
				Enabled: true,
			},
			wantErr: true,
		},
		{
			name: "enabled with API key",
			config: &config.VirusTotalConfig{
				Enabled: true,
				APIKey:  "test-api-key",
				MaxFileSize: "32MB",
			},
			wantErr: false,
			wantEnabled: true,
		},
		{
			name: "invalid max file size",
			config: &config.VirusTotalConfig{
				Enabled: true,
				APIKey:  "test-api-key",
				MaxFileSize: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.config)
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			assert.NotNil(t, scanner)
			assert.Equal(t, tt.wantEnabled, scanner.IsEnabled())
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		{"1024", 1024, false},
		{"1KB", 1024, false},
		{"1kb", 1024, false},
		{"10MB", 10 * 1024 * 1024, false},
		{"10mb", 10 * 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"32MB", 32 * 1024 * 1024, false},
		{"100B", 100, false},
		{"invalid", 0, true},
		{"", 0, true},
		{"-10MB", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseSize(tt.input)
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScannerScanReader(t *testing.T) {
	// Test with disabled scanner
	disabledScanner := &Scanner{
		enabled: false,
	}
	
	result, err := disabledScanner.ScanReader(context.Background(), nil, "test.txt", 1024)
	assert.NoError(t, err)
	assert.Nil(t, result)
	
	// Test with scan uploads disabled
	noScanScanner := &Scanner{
		enabled: true,
		config: &config.VirusTotalConfig{
			ScanUploads: false,
		},
	}
	
	result, err = noScanScanner.ScanReader(context.Background(), nil, "test.txt", 1024)
	assert.NoError(t, err)
	assert.Nil(t, result)
	
	// Test file too large
	largeSizeScanner := &Scanner{
		enabled: true,
		maxFileSize: 1024,
		config: &config.VirusTotalConfig{
			ScanUploads: true,
		},
		logger: logrus.WithField("test", true),
	}
	
	result, err = largeSizeScanner.ScanReader(context.Background(), nil, "large.bin", 2048)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestShouldBlockUpload(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		config   *config.VirusTotalConfig
		result   *ScanResult
		expected bool
	}{
		{
			name:     "disabled scanner",
			enabled:  false,
			result:   &ScanResult{Malicious: 5},
			expected: false,
		},
		{
			name:    "nil result",
			enabled: true,
			config:  &config.VirusTotalConfig{BlockThreats: true},
			result:  nil,
			expected: false,
		},
		{
			name:    "block threats disabled",
			enabled: true,
			config:  &config.VirusTotalConfig{BlockThreats: false},
			result:  &ScanResult{Malicious: 5},
			expected: false,
		},
		{
			name:    "clean file",
			enabled: true,
			config:  &config.VirusTotalConfig{BlockThreats: true},
			result:  &ScanResult{Malicious: 0, Suspicious: 0},
			expected: false,
		},
		{
			name:    "malicious file",
			enabled: true,
			config:  &config.VirusTotalConfig{BlockThreats: true},
			result:  &ScanResult{Malicious: 5},
			expected: true,
		},
		{
			name:    "suspicious file",
			enabled: true,
			config:  &config.VirusTotalConfig{BlockThreats: true},
			result:  &ScanResult{Suspicious: 3},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &Scanner{
				enabled: tt.enabled,
				config:  tt.config,
			}
			
			result := scanner.ShouldBlockUpload(tt.result)
			assert.Equal(t, tt.expected, result)
		})
	}
}