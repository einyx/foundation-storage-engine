package storage

import (
	"io"
	"sync"
)

// StreamingReader wraps a non-seekable reader and provides a seekable interface
// by buffering data on-demand. This is used for large multipart uploads.
type StreamingReader struct {
	reader io.Reader
	buffer []byte
	pos    int64
	size   int64
	mu     sync.Mutex
	eof    bool
}

// NewStreamingReader creates a new streaming reader
func NewStreamingReader(r io.Reader, size int64) *StreamingReader {
	return &StreamingReader{
		reader: r,
		size:   size,
		buffer: make([]byte, 0, 1024*1024), // Start with 1MB buffer
	}
}

// Read implements io.Reader
func (s *StreamingReader) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If we have buffered data, read from it first
	if s.pos < int64(len(s.buffer)) {
		n = copy(p, s.buffer[s.pos:])
		s.pos += int64(n)
		if n > 0 {
			return n, nil
		}
	}

	// If we've reached EOF previously, return it
	if s.eof {
		return 0, io.EOF
	}

	// Read more data from the underlying reader
	tempBuf := make([]byte, len(p))
	n, err = s.reader.Read(tempBuf)
	if n > 0 {
		// Append to our buffer for potential future seeks
		s.buffer = append(s.buffer, tempBuf[:n]...)
		// Copy to output
		copy(p, tempBuf[:n])
		s.pos += int64(n)
	}

	if err == io.EOF {
		s.eof = true
	}

	return n, err
}

// Seek implements io.Seeker
func (s *StreamingReader) Seek(offset int64, whence int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = s.pos + offset
	case io.SeekEnd:
		newPos = s.size + offset
	default:
		return 0, io.ErrNoProgress
	}

	if newPos < 0 {
		return 0, io.ErrNoProgress
	}

	// If seeking within buffered data, just update position
	if newPos <= int64(len(s.buffer)) {
		s.pos = newPos
		return newPos, nil
	}

	// If seeking forward beyond buffer, we need to read and discard data
	if newPos > int64(len(s.buffer)) && !s.eof {
		// Read and buffer data until we reach the desired position
		toRead := newPos - int64(len(s.buffer))
		discardBuf := make([]byte, 32*1024) // 32KB chunks
		
		for toRead > 0 && !s.eof {
			readSize := toRead
			if readSize > int64(len(discardBuf)) {
				readSize = int64(len(discardBuf))
			}
			
			n, err := s.reader.Read(discardBuf[:readSize])
			if n > 0 {
				s.buffer = append(s.buffer, discardBuf[:n]...)
				toRead -= int64(n)
			}
			
			if err == io.EOF {
				s.eof = true
				break
			} else if err != nil {
				return s.pos, err
			}
		}
	}

	// Update position
	if newPos > int64(len(s.buffer)) {
		s.pos = int64(len(s.buffer))
	} else {
		s.pos = newPos
	}

	return s.pos, nil
}

// Close implements io.Closer
func (s *StreamingReader) Close() error {
	if closer, ok := s.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}