package storage

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	
	"github.com/sirupsen/logrus"
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
		reader:     bufio.NewReaderSize(r, 2*1024*1024), // 2MB buffer for large chunks
		readBuffer: make([]byte, 1024*1024), // 1MB reusable buffer
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
		logrus.WithFields(logrus.Fields{
			"error": err,
			"bytesRead": d.bytesRead,
		}).Debug("Chunk header read error")
		return 0, err
	}

	// Handle final chunk
	if size == 0 {
		// Read trailing data
		_, _ = d.reader.Discard(2) // Final CRLF
		d.done = true
		logrus.WithField("totalBytesRead", d.bytesRead).Debug("Finished reading all chunks")
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
			// Log the problematic header for debugging
			logrus.WithFields(logrus.Fields{
				"header": header,
				"sizeStr": sizeStr,
				"error": parseErr,
			}).Error("Failed to parse chunk size")
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
	// Protect against unreasonably large chunks that could cause OOM
	const maxChunkSize = 100 * 1024 * 1024 // 100MB max chunk
	if chunkSize > maxChunkSize {
		return 0, fmt.Errorf("chunk size too large: %d bytes (max: %d)", chunkSize, maxChunkSize)
	}
	
	// Read directly into the output buffer when possible
	toRead := int64(len(p))
	if toRead > chunkSize {
		toRead = chunkSize
	}

	// Read with timeout to avoid hanging
	totalRead := 0
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	for totalRead < int(toRead) {
		// Check for timeout
		select {
		case <-ctx.Done():
			return totalRead, fmt.Errorf("chunk read timeout after 30 seconds")
		default:
		}
		
		n, err := d.reader.Read(p[totalRead:toRead])
		totalRead += n
		if err != nil {
			if err == io.EOF && totalRead > 0 {
				break // We got some data before EOF
			}
			return totalRead, fmt.Errorf("failed to read chunk data: %w", err)
		}
		
		// If no progress is made, break to avoid infinite loop
		if n == 0 {
			break
		}
	}
	n := totalRead

	d.bytesRead += int64(n)
	d.chunkSize = chunkSize

	// If we read less than the chunk size, we need to handle the remaining data
	if int64(n) < chunkSize {
		// Read remaining chunk data into internal buffer
		remaining := chunkSize - int64(n)
		
		// Protect against unreasonably large allocations
		if remaining > maxChunkSize {
			return n, fmt.Errorf("chunk size too large: %d bytes", remaining)
		}
		
		d.currentChunk = make([]byte, remaining)
		
		// Use timeout for ReadFull to prevent hanging
		readCtx, readCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer readCancel()
		
		// Read remaining data with timeout
		err := d.readFullWithTimeout(readCtx, d.currentChunk)
		if err != nil {
			return n, fmt.Errorf("failed to read remaining chunk data: %w", err)
		}
		d.currentChunkPos = 0
	}

	// Read trailing CRLF with timeout
	crlf := make([]byte, 2)
	crlfCtx, crlfCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer crlfCancel()
	
	if err := d.readFullWithTimeout(crlfCtx, crlf); err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			// This might be the last chunk without trailing CRLF
			// Log but continue anyway
			logrus.WithError(err).Debug("Failed to read trailing CRLF, continuing")
		}
	}

	return n, nil
}

// readFullWithTimeout reads exactly len(buf) bytes with a timeout
func (d *AWSChunkDecoder) readFullWithTimeout(ctx context.Context, buf []byte) error {
	total := 0
	for total < len(buf) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("read timeout: %w", ctx.Err())
		default:
		}
		
		n, err := d.reader.Read(buf[total:])
		total += n
		if err != nil {
			if err == io.EOF && total > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		
		// If no progress is made, return error to avoid infinite loop
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (d *AWSChunkDecoder) readLine() (string, error) {
	// Add timeout to prevent hanging on ReadString
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Read line with timeout
	lineChan := make(chan string, 1)
	errChan := make(chan error, 1)
	
	go func() {
		line, err := d.reader.ReadString('\n')
		if err != nil {
			errChan <- err
			return
		}
		
		// Trim line ending
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		
		lineChan <- line
	}()
	
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("readline timeout after 10 seconds")
	case line := <-lineChan:
		return line, nil
	case err := <-errChan:
		return "", err
	}
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
