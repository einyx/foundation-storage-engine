package storage

import (
	"io"
	"sync"
)

// BufferedReader provides a buffered reader with prefetching for smooth transfers
type BufferedReader struct {
	reader    io.Reader
	buffer    []byte
	readAhead []byte
	pos       int
	size      int
	mu        sync.Mutex
	prefetch  chan []byte
	done      chan bool
	err       error
}

// NewBufferedReader creates a new buffered reader with prefetching
func NewBufferedReader(r io.Reader, bufferSize int) *BufferedReader {
	br := &BufferedReader{
		reader:    r,
		buffer:    make([]byte, bufferSize),
		readAhead: make([]byte, bufferSize),
		prefetch:  make(chan []byte, 1),
		done:      make(chan bool),
	}
	
	// Start prefetching goroutine
	go br.prefetcher()
	
	// Prime the buffer
	br.fillBuffer()
	
	return br
}

func (br *BufferedReader) prefetcher() {
	for {
		select {
		case <-br.done:
			return
		default:
			// Read ahead into secondary buffer
			buf := make([]byte, len(br.readAhead))
			n, err := io.ReadFull(br.reader, buf)
			if n > 0 {
				select {
				case br.prefetch <- buf[:n]:
				case <-br.done:
					return
				}
			}
			if err != nil {
				br.mu.Lock()
				br.err = err
				br.mu.Unlock()
				return
			}
		}
	}
}

func (br *BufferedReader) fillBuffer() {
	select {
	case data := <-br.prefetch:
		br.buffer = data
		br.size = len(data)
		br.pos = 0
	default:
		// No prefetched data, read directly
		n, err := br.reader.Read(br.buffer)
		br.size = n
		br.pos = 0
		if err != nil {
			br.err = err
		}
	}
}

func (br *BufferedReader) Read(p []byte) (int, error) {
	br.mu.Lock()
	defer br.mu.Unlock()
	
	if br.pos >= br.size {
		br.fillBuffer()
		if br.size == 0 {
			return 0, br.err
		}
	}
	
	n := copy(p, br.buffer[br.pos:br.size])
	br.pos += n
	return n, nil
}

func (br *BufferedReader) Close() error {
	close(br.done)
	return nil
}