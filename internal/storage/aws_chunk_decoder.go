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
	reader    *bufio.Reader
	buffer    bytes.Buffer
	done      bool
	bytesRead int64
}

// NewAWSChunkDecoder creates a new chunk decoder
func NewAWSChunkDecoder(r io.Reader) *AWSChunkDecoder {
	return &AWSChunkDecoder{
		reader: bufio.NewReader(r),
	}
}

func (d *AWSChunkDecoder) Read(p []byte) (int, error) {
	if d.done {
		return 0, io.EOF
	}

	// Return buffered data first
	if d.buffer.Len() > 0 {
		return d.buffer.Read(p)
	}

	// Read next chunk
	if err := d.readNextChunk(); err != nil {
		if err == io.EOF {
			d.done = true
			if d.buffer.Len() > 0 {
				return d.buffer.Read(p)
			}
		}
		return 0, err
	}

	return d.buffer.Read(p)
}

func (d *AWSChunkDecoder) readNextChunk() error {
	// Read chunk header line
	header, err := d.readLine()
	if err != nil {
		return err
	}

	if header == "" {
		return io.EOF
	}

	// Parse chunk size from header
	// Format: hex-size;chunk-signature=signature
	size := int64(0)
	if idx := strings.Index(header, ";chunk-signature="); idx > 0 {
		sizeStr := header[:idx]
		parsedSize, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			return fmt.Errorf("invalid chunk size '%s': %w", sizeStr, parseErr)
		}
		size = parsedSize
	} else {
		// Try to parse as plain hex (for simple chunks)
		parsedSize, parseErr := strconv.ParseInt(header, 16, 64)
		if parseErr != nil {
			return fmt.Errorf("invalid chunk header '%s': %w", header, parseErr)
		}
		size = parsedSize
	}

	// Handle final chunk
	if size == 0 {
		// Read trailing data
		_, _ = d.reader.Discard(2) // Final CRLF
		return io.EOF
	}

	// Read chunk data
	chunkData := make([]byte, size)
	n, err := io.ReadFull(d.reader, chunkData)
	if err != nil {
		return fmt.Errorf("failed to read chunk data: %w", err)
	}

	d.bytesRead += int64(n)

	// Read trailing CRLF (if present)
	// Some implementations may not include trailing CRLF on the last chunk
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(d.reader, crlf); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// This is likely the last chunk without trailing CRLF
			// This is acceptable - just continue
		} else {
			return fmt.Errorf("error reading chunk trailing CRLF: %w", err)
		}
	}

	// Buffer the chunk data
	d.buffer.Write(chunkData)

	return nil
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
