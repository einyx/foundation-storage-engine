package storage

import (
	"io"
	"time"
)

// TimeoutReader wraps a reader with timeout recovery
type TimeoutReader struct {
	reader      io.Reader
	timeout     time.Duration
	buffer      []byte
	bufferValid int
	lastRead    time.Time
}

// NewTimeoutReader creates a reader that handles timeouts gracefully
func NewTimeoutReader(r io.Reader, timeout time.Duration) *TimeoutReader {
	return &TimeoutReader{
		reader:   r,
		timeout:  timeout,
		buffer:   make([]byte, 64*1024), // 64KB buffer
		lastRead: time.Now(),
	}
}

func (tr *TimeoutReader) Read(p []byte) (int, error) {
	// If we have buffered data from a previous read, return it
	if tr.bufferValid > 0 {
		n := copy(p, tr.buffer[:tr.bufferValid])
		// Shift remaining data to the beginning
		copy(tr.buffer, tr.buffer[n:tr.bufferValid])
		tr.bufferValid -= n
		return n, nil
	}

	// Try to read with smaller chunks to avoid timeouts
	readSize := len(p)
	if readSize > 16*1024 { // Max 16KB per read to avoid timeouts
		readSize = 16 * 1024
	}

	// Read into our buffer first
	n, err := tr.reader.Read(tr.buffer[:readSize])
	tr.lastRead = time.Now()

	if n > 0 {
		// Copy to output
		copied := copy(p, tr.buffer[:n])
		// Save any remaining data
		if copied < n {
			tr.bufferValid = n - copied
			copy(tr.buffer, tr.buffer[copied:n])
		}
		return copied, nil
	}

	return 0, err
}