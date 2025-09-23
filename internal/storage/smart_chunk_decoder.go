package storage

import (
	"bufio"
	"io"
	"strings"
	"time"
	
	"github.com/sirupsen/logrus"
)

// SmartChunkDecoder wraps the AWS chunk decoder and falls back to raw reading
// when it detects that the client sent raw data despite declaring chunked encoding
type SmartChunkDecoder struct {
	reader       io.Reader
	bufReader    *bufio.Reader
	isChunked    bool
	decoder      io.Reader
	checkedFirst bool
	rawFallback  bool
}

// NewSmartChunkDecoder creates a decoder that can handle both chunked and raw data
func NewSmartChunkDecoder(r io.Reader) *SmartChunkDecoder {
	return &SmartChunkDecoder{
		reader:    r,
		bufReader: bufio.NewReaderSize(r, 1024*1024), // Increased to 1MB for large JSON data
		isChunked: true, // Assume chunked initially
	}
}

func (d *SmartChunkDecoder) Read(p []byte) (int, error) {
	// First time reading, check if it's actually chunked
	if !d.checkedFirst {
		d.checkedFirst = true
		detectionStart := time.Now()
		
		// Peek at the first line to see if it looks like a chunk header
		// Reduced peek size for faster detection
		firstLine, err := d.bufReader.Peek(256)
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return 0, err
		}
		
		// Find the end of the first line
		lineEnd := -1
		for i, b := range firstLine {
			if b == '\n' {
				lineEnd = i
				break
			}
		}
		
		// If no newline found in peek, check the whole peeked data
		if lineEnd < 0 && len(firstLine) > 0 {
			lineEnd = len(firstLine)
		}
		
		if lineEnd > 0 {
			line := string(firstLine[:lineEnd])
			line = strings.TrimSuffix(line, "\r")
			
			// Log what we're detecting
			logrus.WithFields(logrus.Fields{
				"firstLine": line,
				"lineLength": len(line),
			}).Debug("SmartChunkDecoder: Analyzing first line")
			
			// Check if this looks like a valid chunk header
			if !d.isValidChunkHeader(line) {
				// Not chunked, use raw reader
				logrus.Info("SmartChunkDecoder: Detected raw data, switching to raw mode")
				d.rawFallback = true
				d.decoder = d.bufReader
			} else {
				logrus.Info("SmartChunkDecoder: Detected chunked data")
			}
		} else {
			// No data or can't determine, assume raw
			logrus.Info("SmartChunkDecoder: No data to analyze, assuming raw mode")
			d.rawFallback = true
			d.decoder = d.bufReader
		}
		
		// If we haven't determined it's raw, use chunk decoder
		if !d.rawFallback {
			d.decoder = &AWSChunkDecoder{
				reader:     d.bufReader,
				readBuffer: make([]byte, 1024*1024), // Increased to 1MB for large data
			}
		}
		
		// Log detection time
		detectionDuration := time.Since(detectionStart)
		logrus.WithFields(logrus.Fields{
			"duration": detectionDuration,
			"mode":     map[bool]string{true: "raw", false: "chunked"}[d.rawFallback],
		}).Debug("SmartChunkDecoder: Detection completed")
	}
	
	return d.decoder.Read(p)
}

// isValidChunkHeader checks if the line looks like a valid AWS chunk header
func (d *SmartChunkDecoder) isValidChunkHeader(line string) bool {
	if line == "" {
		return false
	}
	
	// Check for JSON-like content (common in Iceberg metadata)
	if strings.Contains(line, "\"") || strings.Contains(line, "{") || strings.Contains(line, "}") {
		return false
	}
	
	// Split by semicolon to get just the size part
	sizePart := line
	if idx := strings.Index(line, ";"); idx > 0 {
		sizePart = line[:idx]
	}
	
	// Empty size part is not valid
	if sizePart == "" {
		return false
	}
	
	// A valid chunk size should only contain hex digits (0-9, a-f, A-F)
	for _, ch := range sizePart {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	
	// Additional check: chunk sizes are typically not too long
	// (16 hex digits = 64-bit max value)
	if len(sizePart) > 16 {
		return false
	}
	
	return true
}

// IsRawFallback returns whether the decoder fell back to raw mode
func (d *SmartChunkDecoder) IsRawFallback() bool {
	return d.rawFallback
}