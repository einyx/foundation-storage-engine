package storage

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	
	"github.com/sirupsen/logrus"
)

// FastChunkReader is an optimized chunk reader for multipart uploads
// It avoids buffering entire chunks and streams data efficiently
type FastChunkReader struct {
	reader        *bufio.Reader
	remaining     int64
	done          bool
	isChunked     bool
	checkedFirst  bool
}

// NewFastChunkReader creates a new optimized chunk reader
func NewFastChunkReader(r io.Reader) *FastChunkReader {
	return &FastChunkReader{
		reader:    bufio.NewReaderSize(r, 64*1024), // 64KB buffer
		isChunked: true,
	}
}

func (r *FastChunkReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}

	// First read - detect if actually chunked
	if !r.checkedFirst {
		r.checkedFirst = true
		
		// Peek at first few bytes to detect format
		peek, err := r.reader.Peek(64)
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return 0, err
		}
		
		// Detect data format to determine if chunked encoding is used
		if len(peek) > 0 {
			// Check for JSON or binary data
			if bytes.Contains(peek, []byte("{")) || bytes.Contains(peek, []byte("\"")) {
				r.isChunked = false
				logrus.Debug("FastChunkReader: Detected raw JSON data")
			} else if peek[0] < 32 || peek[0] > 126 {
				r.isChunked = false
				logrus.Debug("FastChunkReader: Detected binary data")
			}
		}
	}

	// If not chunked, just pass through
	if !r.isChunked {
		return r.reader.Read(p)
	}

	// If we have remaining data from current chunk, read it
	if r.remaining > 0 {
		toRead := len(p)
		if int64(toRead) > r.remaining {
			toRead = int(r.remaining)
		}
		
		n, err := r.reader.Read(p[:toRead])
		r.remaining -= int64(n)
		
		if r.remaining == 0 {
			// Skip trailing CRLF
			r.reader.Discard(2)
		}
		
		return n, err
	}

	// Read next chunk header
	header, err := r.readLine()
	if err != nil {
		return 0, err
	}

	// Parse chunk size
	chunkSize, err := r.parseChunkSize(header)
	if err != nil {
		// Might be raw data after all
		if r.looksLikeRawData(header) {
			r.isChunked = false
			// Put the header back by creating a multi-reader
			headerReader := strings.NewReader(header + "\n")
			r.reader = bufio.NewReaderSize(io.MultiReader(headerReader, r.reader), 64*1024)
			return r.Read(p)
		}
		return 0, err
	}

	// Check for final chunk
	if chunkSize == 0 {
		r.done = true
		r.reader.Discard(2) // Final CRLF
		return 0, io.EOF
	}

	r.remaining = chunkSize
	return r.Read(p) // Recursive call to read the chunk data
}

func (r *FastChunkReader) readLine() (string, error) {
	line, err := r.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func (r *FastChunkReader) parseChunkSize(header string) (int64, error) {
	// Extract size part (before semicolon)
	sizePart := header
	if idx := strings.Index(header, ";"); idx > 0 {
		sizePart = header[:idx]
	}
	
	size, err := strconv.ParseInt(sizePart, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid chunk size: %s", sizePart)
	}
	
	return size, nil
}

func (r *FastChunkReader) looksLikeRawData(header string) bool {
	if header == "" {
		return false
	}
	
	// Check for non-hex characters in size part
	sizePart := header
	if idx := strings.Index(header, ";"); idx > 0 {
		sizePart = header[:idx]
	}
	
	for _, ch := range sizePart {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return true
		}
	}
	
	return false
}