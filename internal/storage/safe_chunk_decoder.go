package storage

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// SafeChunkDecoder wraps AWSChunkDecoder with early validation to prevent corruption
type SafeChunkDecoder struct {
	reader      io.Reader
	decoder     *AWSChunkDecoder
	validated   bool
	fallbackRaw bool
}

// NewSafeChunkDecoder creates a chunk decoder that validates the first chunk before proceeding
func NewSafeChunkDecoder(r io.Reader) *SafeChunkDecoder {
	return &SafeChunkDecoder{
		reader: r,
	}
}

func (s *SafeChunkDecoder) Read(p []byte) (int, error) {
	if !s.validated {
		s.validated = true
		
		// Peek at the first line to validate it's actually chunked
		bufReader := bufio.NewReader(s.reader)
		firstLine, err := bufReader.ReadString('\n')
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("failed to read first line for validation: %w", err)
		}
		
		// Create a reader that includes what we peeked
		s.reader = io.MultiReader(strings.NewReader(firstLine), bufReader)
		
		// Validate the first line looks like a chunk header
		cleanFirstLine := strings.TrimSuffix(firstLine, "\n")
		if !s.isValidChunkHeader(cleanFirstLine) {
			logrus.WithFields(logrus.Fields{
				"firstLine": cleanFirstLine,
				"firstBytes": []byte(cleanFirstLine)[:minInt(len(cleanFirstLine), 16)],
			}).Warn("Data does not appear to be chunked - falling back to raw mode")
			s.fallbackRaw = true
			// Don't create decoder, just pass through
		} else {
			s.decoder = NewAWSChunkDecoder(s.reader)
			logrus.WithField("chunkSize", cleanFirstLine).Debug("Validated chunk format - using AWS chunk decoder")
		}
	}
	
	if s.fallbackRaw {
		return s.reader.Read(p)
	}
	
	return s.decoder.Read(p)
}

// Close implements io.Closer to satisfy io.ReadCloser interface
func (s *SafeChunkDecoder) Close() error {
	if closer, ok := s.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// isValidChunkHeader validates that a line looks like a proper AWS chunk header
func (s *SafeChunkDecoder) isValidChunkHeader(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	
	// Check for binary content or Parquet magic bytes
	lineBytes := []byte(line)
	for _, b := range lineBytes {
		if b < 32 && b != '\t' && b != '\r' && b != '\n' {
			return false
		}
	}
	
	// Check for Parquet file magic bytes "PAR1" at start
	if len(lineBytes) >= 4 && string(lineBytes[:4]) == "PAR1" {
		return false
	}
	
	// Split by semicolon to get size part
	sizePart := line
	if idx := strings.Index(line, ";"); idx > 0 {
		sizePart = line[:idx]
	}
	
	// Must be 1-8 hex characters
	if len(sizePart) < 1 || len(sizePart) > 8 {
		return false
	}
	
	// Must be valid hex
	for _, ch := range sizePart {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	
	// Must parse to reasonable size (allow up to 1GB chunks)
	size, err := strconv.ParseInt(sizePart, 16, 64)
	if err != nil || size < 0 || size > 1024*1024*1024 {
		return false
	}
	
	return true
}

// IsRawFallback returns whether the decoder fell back to raw mode
func (s *SafeChunkDecoder) IsRawFallback() bool {
	return s.fallbackRaw
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}