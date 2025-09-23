package virustotal

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	
	"github.com/einyx/foundation-storage-engine/internal/config"
)

// Scanner provides file scanning capabilities using VirusTotal
type Scanner struct {
	client      *Client
	config      *config.VirusTotalConfig
	logger      *logrus.Entry
	enabled     bool
	maxFileSize int64
}

// NewScanner creates a new VirusTotal scanner
func NewScanner(cfg *config.VirusTotalConfig) (*Scanner, error) {
	if cfg == nil || !cfg.Enabled {
		return &Scanner{
			enabled: false,
			logger:  logrus.WithField("module", "virustotal"),
		}, nil
	}
	
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("VirusTotal API key is required when enabled")
	}
	
	// Parse max file size
	maxFileSize, err := parseSize(cfg.MaxFileSize)
	if err != nil {
		return nil, fmt.Errorf("invalid max_file_size: %w", err)
	}
	
	client := NewClient(cfg.APIKey, maxFileSize)
	
	return &Scanner{
		client:      client,
		config:      cfg,
		enabled:     true,
		maxFileSize: maxFileSize,
		logger:      logrus.WithField("module", "virustotal"),
	}, nil
}

// ScanReader scans content from an io.Reader
func (s *Scanner) ScanReader(ctx context.Context, reader io.Reader, filename string, size int64) (*ScanResult, error) {
	if !s.enabled {
		return nil, nil
	}
	
	if !s.config.ScanUploads {
		return nil, nil
	}
	
	// Check file size
	if size > s.maxFileSize {
		s.logger.WithFields(logrus.Fields{
			"filename": filename,
			"size":     size,
			"maxSize":  s.maxFileSize,
		}).Info("File too large for VirusTotal scanning")
		return nil, nil
	}
	
	return s.client.ScanFile(ctx, reader, filename, size)
}

// ShouldBlockUpload determines if an upload should be blocked based on scan results
func (s *Scanner) ShouldBlockUpload(result *ScanResult) bool {
	if !s.enabled || result == nil {
		return false
	}
	
	return s.config.BlockThreats && result.IsThreat()
}

// IsEnabled returns whether scanning is enabled
func (s *Scanner) IsEnabled() bool {
	return s.enabled
}

// parseSize parses a size string like "32MB" into bytes
func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))
	
	multiplier := int64(1)
	if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		sizeStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "GB")
	} else if strings.HasSuffix(sizeStr, "B") {
		sizeStr = strings.TrimSuffix(sizeStr, "B")
	}
	
	value, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		return 0, err
	}
	
	return value * multiplier, nil
}