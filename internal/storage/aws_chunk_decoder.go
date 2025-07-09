package storage

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// AWSChunkDecoder decodes AWS V4 streaming chunks without validation
// It strips chunk headers and signatures, returning only the actual data
type AWSChunkDecoder struct {
	reader          *bufio.Reader
	buffer          bytes.Buffer
	done            bool
	bytesRead       int64
	currentChunk    []byte
	currentChunkPos int
	chunkSize       int64
	readBuffer      []byte // Reusable read buffer
}

// NewAWSChunkDecoder creates a new chunk decoder
func NewAWSChunkDecoder(r io.Reader) *AWSChunkDecoder {
	return &AWSChunkDecoder{
		reader:     bufio.NewReaderSize(r, 1024*1024), // 1MB buffer for smooth reading
		readBuffer: make([]byte, 256*1024), // 256KB reusable buffer
	}
}

func (d *AWSChunkDecoder) Read(p []byte) (int, error) {
	if d.done {
		return 0, io.EOF
	}

	// If we have data in current chunk, return it
	if d.currentChunk != nil && d.currentChunkPos < len(d.currentChunk) {
		n := copy(p, d.currentChunk[d.currentChunkPos:])
		d.currentChunkPos += n
		if d.currentChunkPos >= len(d.currentChunk) {
			// Finished this chunk, clear it
			d.currentChunk = nil
			d.currentChunkPos = 0
		}
		return n, nil
	}

	// Need to read next chunk header
	size, err := d.readChunkHeader()
	if err != nil {
		if err == io.EOF {
			d.done = true
		}
		return 0, err
	}

	// Handle final chunk
	if size == 0 {
		// Read trailing data
		_, _ = d.reader.Discard(2) // Final CRLF
		d.done = true
		return 0, io.EOF
	}

	// Stream chunk data directly to output buffer
	return d.streamChunkData(p, size)
}

func (d *AWSChunkDecoder) readChunkHeader() (int64, error) {
	// Read chunk header line
	header, err := d.readLine()
	if err != nil {
		return 0, err
	}

	if header == "" {
		return 0, io.EOF
	}

	// Parse chunk size from header
	// Format: hex-size;chunk-signature=signature
	size := int64(0)
	if idx := strings.Index(header, ";chunk-signature="); idx > 0 {
		sizeStr := header[:idx]
		parsedSize, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			// Check if this looks like raw data instead of a chunk header
			// This can happen when clients incorrectly declare chunked encoding
			if d.looksLikeRawData(header) {
				return 0, fmt.Errorf("client declared chunked encoding but sent raw data")
			}
			return 0, fmt.Errorf("invalid chunk size '%s': %w", sizeStr, parseErr)
		}
		size = parsedSize
	} else {
		// Try to parse as plain hex (for simple chunks)
		parsedSize, parseErr := strconv.ParseInt(header, 16, 64)
		if parseErr != nil {
			// Check if this looks like raw data instead of a chunk header
			if d.looksLikeRawData(header) {
				return 0, fmt.Errorf("client declared chunked encoding but sent raw data")
			}
			return 0, fmt.Errorf("invalid chunk header '%s': %w", header, parseErr)
		}
		size = parsedSize
	}

	return size, nil
}

func (d *AWSChunkDecoder) streamChunkData(p []byte, chunkSize int64) (int, error) {
	// Read directly into the output buffer when possible
	toRead := int64(len(p))
	if toRead > chunkSize {
		toRead = chunkSize
	}

	// Read in smaller chunks to avoid timeouts
	totalRead := 0
	for totalRead < int(toRead) {
		n, err := d.reader.Read(p[totalRead:toRead])
		totalRead += n
		if err != nil {
			if err == io.EOF && totalRead > 0 {
				break // We got some data before EOF
			}
			return totalRead, fmt.Errorf("failed to read chunk data: %w", err)
		}
	}
	n := totalRead

	d.bytesRead += int64(n)
	d.chunkSize = chunkSize

	// If we read less than the chunk size, we need to handle the remaining data
	if int64(n) < chunkSize {
		// Read remaining chunk data into internal buffer
		remaining := chunkSize - int64(n)
		d.currentChunk = make([]byte, remaining)
		_, err := io.ReadFull(d.reader, d.currentChunk)
		if err != nil {
			return n, fmt.Errorf("failed to read remaining chunk data: %w", err)
		}
		d.currentChunkPos = 0
	}

	// Read trailing CRLF
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(d.reader, crlf); err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			// This might be the last chunk without trailing CRLF
			// Continue anyway
		}
	}

	return n, nil
}

func (d *AWSChunkDecoder) readLine() (string, error) {
	line, err := d.reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	// Trim line ending
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")

	return line, nil
}

// GetBytesRead returns the total bytes read (including chunk overhead)
func (d *AWSChunkDecoder) GetBytesRead() int64 {
	return d.bytesRead
}

// looksLikeRawData checks if the header looks like raw data instead of a chunk header
func (d *AWSChunkDecoder) looksLikeRawData(header string) bool {
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
