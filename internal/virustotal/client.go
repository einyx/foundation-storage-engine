// Package virustotal provides a client for scanning files with VirusTotal API
package virustotal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// API endpoints
	baseURL        = "https://www.virustotal.com/api/v3"
	fileUploadURL  = baseURL + "/files"
	fileReportURL  = baseURL + "/files/%s"
	analysisURL    = baseURL + "/analyses/%s"
	
	// API limits
	maxFileSizeDefault = 32 * 1024 * 1024 // 32MB
	apiTimeout         = 30 * time.Second
	pollInterval       = 5 * time.Second
	maxPollAttempts    = 60 // 5 minutes total
)

// Client is the VirusTotal API client
type Client struct {
	apiKey      string
	httpClient  *http.Client
	maxFileSize int64
	logger      *logrus.Entry
}

// ScanResult represents the result of a file scan
type ScanResult struct {
	SHA256      string
	Malicious   int
	Suspicious  int
	Undetected  int
	Harmless    int
	TotalScans  int
	Verdict     string
	Permalink   string
	ScanDate    time.Time
}

// NewClient creates a new VirusTotal client
func NewClient(apiKey string, maxFileSize int64) *Client {
	if maxFileSize <= 0 {
		maxFileSize = maxFileSizeDefault
	}
	
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: apiTimeout,
		},
		maxFileSize: maxFileSize,
		logger:      logrus.WithField("module", "virustotal"),
	}
}

// ScanFile uploads and scans a file with VirusTotal
func (c *Client) ScanFile(ctx context.Context, reader io.Reader, filename string, size int64) (*ScanResult, error) {
	// Check file size
	if size > c.maxFileSize {
		return nil, fmt.Errorf("file size %d exceeds maximum allowed size %d", size, c.maxFileSize)
	}
	
	// Calculate SHA256 while reading
	hasher := sha256.New()
	data, err := io.ReadAll(io.TeeReader(reader, hasher))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))
	
	c.logger.WithFields(logrus.Fields{
		"filename": filename,
		"size":     size,
		"sha256":   sha256Hash,
	}).Info("Scanning file with VirusTotal")
	
	// Check if file was already scanned
	result, err := c.getFileReport(ctx, sha256Hash)
	if err == nil && result != nil {
		c.logger.Info("File already scanned, returning cached result")
		return result, nil
	}
	
	// Upload file for scanning
	analysisID, err := c.uploadFile(ctx, data, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to upload file: %w", err)
	}
	
	// Wait for analysis to complete
	return c.waitForAnalysis(ctx, analysisID, sha256Hash)
}

// CheckHash checks if a file hash was already scanned
func (c *Client) CheckHash(ctx context.Context, sha256Hash string) (*ScanResult, error) {
	return c.getFileReport(ctx, sha256Hash)
}

func (c *Client) uploadFile(ctx context.Context, data []byte, filename string) (string, error) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	
	if _, err := part.Write(data); err != nil {
		return "", err
	}
	
	if err := writer.Close(); err != nil {
		return "", err
	}
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fileUploadURL, &buf)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	
	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed: %s - %s", resp.Status, string(body))
	}
	
	// Parse response
	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	return result.Data.ID, nil
}

func (c *Client) getFileReport(ctx context.Context, sha256Hash string) (*ScanResult, error) {
	url := fmt.Sprintf(fileReportURL, sha256Hash)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("x-apikey", c.apiKey)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // File not found
	}
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get report failed: %s - %s", resp.Status, string(body))
	}
	
	// Parse response
	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate int64  `json:"last_analysis_date"`
				SHA256           string `json:"sha256"`
				Permalink        string `json:"permalink"`
			} `json:"attributes"`
		} `json:"data"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	stats := result.Data.Attributes.LastAnalysisStats
	totalScans := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless
	
	// Determine verdict
	verdict := "clean"
	if stats.Malicious > 0 {
		verdict = "malicious"
	} else if stats.Suspicious > 0 {
		verdict = "suspicious"
	}
	
	return &ScanResult{
		SHA256:     result.Data.Attributes.SHA256,
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Undetected: stats.Undetected,
		Harmless:   stats.Harmless,
		TotalScans: totalScans,
		Verdict:    verdict,
		Permalink:  result.Data.Attributes.Permalink,
		ScanDate:   time.Unix(result.Data.Attributes.LastAnalysisDate, 0),
	}, nil
}

func (c *Client) waitForAnalysis(ctx context.Context, analysisID, sha256Hash string) (*ScanResult, error) {
	url := fmt.Sprintf(analysisURL, analysisID)
	
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
		
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		
		req.Header.Set("x-apikey", c.apiKey)
		
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("get analysis failed: %s - %s", resp.Status, string(body))
		}
		
		var result struct {
			Data struct {
				Attributes struct {
					Status string `json:"status"`
				} `json:"attributes"`
			} `json:"data"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}
		
		if result.Data.Attributes.Status == "completed" {
			// Get the final report
			return c.getFileReport(ctx, sha256Hash)
		}
	}
	
	return nil, fmt.Errorf("analysis timeout after %d attempts", maxPollAttempts)
}

// IsThreat returns true if the scan result indicates a threat
func (r *ScanResult) IsThreat() bool {
	return r.Malicious > 0 || r.Suspicious > 0
}

// GetThreatLevel returns a human-readable threat level
func (r *ScanResult) GetThreatLevel() string {
	if r.Malicious > 0 {
		return fmt.Sprintf("MALICIOUS (%d/%d detections)", r.Malicious, r.TotalScans)
	}
	if r.Suspicious > 0 {
		return fmt.Sprintf("SUSPICIOUS (%d/%d detections)", r.Suspicious, r.TotalScans)
	}
	return fmt.Sprintf("CLEAN (%d/%d scans)", r.Harmless, r.TotalScans)
}