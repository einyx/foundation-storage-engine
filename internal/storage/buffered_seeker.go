package storage

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	
	"github.com/sirupsen/logrus"
)

// BufferedSeeker provides a seekable interface for streaming data
// It buffers data as it's read, allowing limited seeking within the buffer
type BufferedSeeker struct {
	reader     io.Reader
	buffer     *bytes.Buffer
	size       int64
	pos        int64
	mu         sync.Mutex
	readDone   bool
	allData    []byte // Store all data for full seeking capability
	bufferMode bool   // Whether we're in full buffer mode
}

// NewBufferedSeeker creates a new buffered seeker
func NewBufferedSeeker(r io.Reader, size int64) *BufferedSeeker {
	return &BufferedSeeker{
		reader: r,
		buffer: bytes.NewBuffer(make([]byte, 0, 64*1024)), // Start with 64KB
		size:   size,
	}
}

// Read implements io.Reader
func (b *BufferedSeeker) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// If we're reading from a position within the buffer
	if b.pos < int64(b.buffer.Len()) {
		// Create a reader from the buffered data at the current position
		bufferedData := b.buffer.Bytes()[b.pos:]
		n := copy(p, bufferedData)
		b.pos += int64(n)
		
		if n > 0 {
			return n, nil
		}
	}

	// If we've read all buffered data and the reader is done
	if b.readDone {
		return 0, io.EOF
	}

	// Read more data from the underlying reader
	tempBuf := make([]byte, len(p))
	n, err := b.reader.Read(tempBuf)
	
	if n > 0 {
		// Append to buffer for potential future seeks
		b.buffer.Write(tempBuf[:n])
		
		// Copy to output buffer
		copy(p, tempBuf[:n])
		b.pos += int64(n)
	}

	if err == io.EOF {
		b.readDone = true
	}

	return n, err
}

// Seek implements io.Seeker
func (b *BufferedSeeker) Seek(offset int64, whence int) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = b.pos + offset
	case io.SeekEnd:
		// For seeking from end, we need the total size
		if b.size > 0 {
			newPos = b.size + offset
		} else {
			return 0, fmt.Errorf("cannot seek from end: size unknown")
		}
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newPos < 0 {
		return 0, fmt.Errorf("negative position")
	}

	// Can only seek within buffered data
	if newPos > int64(b.buffer.Len()) {
		// If we're seeking forward and haven't finished reading,
		// we need to read and buffer more data
		if !b.readDone && newPos <= b.size {
			toRead := newPos - int64(b.buffer.Len())
			tempBuf := make([]byte, 32*1024) // Read in 32KB chunks
			
			for toRead > 0 && !b.readDone {
				readSize := toRead
				if readSize > int64(len(tempBuf)) {
					readSize = int64(len(tempBuf))
				}
				
				n, err := b.reader.Read(tempBuf[:readSize])
				if n > 0 {
					b.buffer.Write(tempBuf[:n])
					toRead -= int64(n)
				}
				
				if err == io.EOF {
					b.readDone = true
					break
				} else if err != nil {
					return b.pos, err
				}
			}
		}
		
		// Still can't seek there
		if newPos > int64(b.buffer.Len()) {
			return b.pos, fmt.Errorf("cannot seek beyond buffered data")
		}
	}

	b.pos = newPos
	
	logrus.WithFields(logrus.Fields{
		"newPos":      newPos,
		"bufferSize":  b.buffer.Len(),
		"bufferSizeMB": b.buffer.Len() / 1024 / 1024,
	}).Debug("Seek operation completed")
	
	return newPos, nil
}