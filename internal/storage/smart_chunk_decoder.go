package storage

import (
	"bufio"
	"io"
	"strings"
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
		bufReader: bufio.NewReaderSize(r, 64*1024),
		isChunked: true, // Assume chunked initially
	}
}

func (d *SmartChunkDecoder) Read(p []byte) (int, error) {
	// First time reading, check if it's actually chunked
	if !d.checkedFirst {
		d.checkedFirst = true
		
		// Peek at the first line to see if it looks like a chunk header
		firstLine, err := d.bufReader.Peek(1024)
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
			
			// Check if this looks like a valid chunk header
			if !d.isValidChunkHeader(line) {
				// Not chunked, use raw reader
				d.rawFallback = true
				d.decoder = d.bufReader
			}
		} else {
			// No data or can't determine, assume raw
			d.rawFallback = true
			d.decoder = d.bufReader
		}
		
		// If we haven't determined it's raw, use chunk decoder
		if !d.rawFallback {
			d.decoder = &AWSChunkDecoder{
				reader:     d.bufReader,
				readBuffer: make([]byte, 256*1024),
			}
		}
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