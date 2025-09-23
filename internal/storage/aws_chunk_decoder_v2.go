package storage

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// AWSChunkDecoderV2 is an improved decoder that handles timeouts better
type AWSChunkDecoderV2 struct {
	reader         *bufio.Reader
	buffer         []byte
	bufferPos      int
	bufferLen      int
	done           bool
	totalBytesRead int64
	chunkBytesLeft int64
	inTrailer      bool
	lastReadTime   time.Time
	slowReads      int
}

// NewAWSChunkDecoderV2 creates a new improved chunk decoder
func NewAWSChunkDecoderV2(r io.Reader) *AWSChunkDecoderV2 {
	return &AWSChunkDecoderV2{
		reader: bufio.NewReaderSize(r, 256*1024), // 256KB buffer - smaller to prevent bloat
		buffer: make([]byte, 64*1024),            // 64KB working buffer
	}
}

func (d *AWSChunkDecoderV2) Read(p []byte) (int, error) {
	if d.done {
		return 0, io.EOF
	}

	totalRead := 0
	
	for totalRead < len(p) {
		// If we have buffered data, copy it first
		if d.bufferPos < d.bufferLen {
			n := copy(p[totalRead:], d.buffer[d.bufferPos:d.bufferLen])
			d.bufferPos += n
			totalRead += n
			d.totalBytesRead += int64(n)
			continue
		}

		// If we're still reading a chunk, read more chunk data
		if d.chunkBytesLeft > 0 {
			toRead := int64(len(d.buffer))
			if toRead > d.chunkBytesLeft {
				toRead = d.chunkBytesLeft
			}
			
			// Adaptive read size based on performance
			if d.totalBytesRead > 10*1024*1024 {
				// After 10MB, use smaller reads
				if toRead > 16*1024 {
					toRead = 16 * 1024
				}
				// If experiencing slow reads, reduce further
				if d.slowReads > 3 && toRead > 8*1024 {
					toRead = 8 * 1024
				}
			}
			
			// Add small delay if we're reading too fast and causing congestion
			if d.totalBytesRead > 50*1024*1024 && time.Since(d.lastReadTime) < 10*time.Millisecond {
				time.Sleep(20 * time.Millisecond)
			}
			
			start := time.Now()
			n, err := d.reader.Read(d.buffer[:toRead])
			d.lastReadTime = time.Now()
			
			// Track slow reads
			if time.Since(start) > 2*time.Second {
				d.slowReads++
			} else if time.Since(start) < 100*time.Millisecond && d.slowReads > 0 {
				d.slowReads--
			}
			if n > 0 {
				d.bufferLen = n
				d.bufferPos = 0
				d.chunkBytesLeft -= int64(n)
				continue
			}
			if err != nil {
				if err == io.EOF && d.chunkBytesLeft > 0 {
					return totalRead, io.ErrUnexpectedEOF
				}
				return totalRead, err
			}
		}

		// Read trailing CRLF after chunk data
		if d.bufferLen == 0 && d.chunkBytesLeft == 0 && !d.inTrailer {
			// Discard CRLF
			if _, err := d.reader.Discard(2); err != nil && err != io.EOF {
				// Ignore CRLF read errors, some implementations don't send it
			}
			d.inTrailer = true
		}

		// Read next chunk header
		header, err := d.readLine()
		if err != nil {
			if err == io.EOF && totalRead > 0 {
				return totalRead, nil
			}
			return totalRead, err
		}

		// Parse chunk size
		size, err := d.parseChunkSize(header)
		if err != nil {
			return totalRead, err
		}

		// Check for final chunk
		if size == 0 {
			// Read any trailing headers
			for {
				line, err := d.readLine()
				if err != nil || line == "" {
					break
				}
			}
			d.done = true
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, io.EOF
		}

		d.chunkBytesLeft = size
		d.inTrailer = false
	}

	return totalRead, nil
}

func (d *AWSChunkDecoderV2) readLine() (string, error) {
	// Set timeout for reading lines
	line, err := d.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	
	// Trim line endings
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	
	return line, nil
}

func (d *AWSChunkDecoderV2) parseChunkSize(header string) (int64, error) {
	if header == "" {
		return 0, io.EOF
	}

	// Format: hex-size[;chunk-signature=signature]
	parts := strings.SplitN(header, ";", 2)
	if len(parts) == 0 {
		return 0, fmt.Errorf("invalid chunk header: %s", header)
	}

	size, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil {
		// Check if this looks like raw data instead of a chunk header
		// This can happen when clients incorrectly declare chunked encoding
		if d.looksLikeRawData(header) {
			return 0, fmt.Errorf("client declared chunked encoding but sent raw data")
		}
		return 0, fmt.Errorf("invalid chunk size '%s': %w", parts[0], err)
	}

	return size, nil
}

// GetBytesRead returns total bytes read
func (d *AWSChunkDecoderV2) GetBytesRead() int64 {
	return d.totalBytesRead
}

// looksLikeRawData checks if the header looks like raw data instead of a chunk header
func (d *AWSChunkDecoderV2) looksLikeRawData(header string) bool {
	// AWS chunk headers should be hex digits, optionally followed by ;chunk-signature=
	// If we see common data patterns, it's likely raw data
	
	// Check for JSON-like content (common in Iceberg metadata)
	if strings.Contains(header, "\"") || strings.Contains(header, "{") || strings.Contains(header, "}") {
		return true
	}
	
	// Check for Avro magic bytes or binary content
	if len(header) > 0 && (header[0] < 32 || header[0] > 126) {
		return true
	}
	
	// Check if it starts with text that's clearly not hex
	if len(header) > 0 {
		// Split by semicolon to get just the size part
		sizePart := header
		if idx := strings.Index(header, ";"); idx > 0 {
			sizePart = header[:idx]
		}
		
		// A valid chunk size should only contain hex digits (0-9, a-f, A-F)
		for _, ch := range sizePart {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return true
			}
		}
	}
	
	return false
}

// SetReadTimeout sets a timeout for read operations
func (d *AWSChunkDecoderV2) SetReadTimeout(timeout time.Duration) {
	// This would need to be implemented with a custom reader that supports timeouts
	// For now, we rely on the underlying transport timeouts
}