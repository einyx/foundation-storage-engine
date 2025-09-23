package storage

import (
	"fmt"
	"io"
	"sync"
	
	"github.com/sirupsen/logrus"
)

// ChunkedUploadReader provides a seekable interface for large uploads
// by reading data in chunks and caching only what's needed
type ChunkedUploadReader struct {
	reader    io.Reader
	size      int64
	chunkSize int64
	chunks    map[int64][]byte
	mu        sync.RWMutex
	position  int64
}

// NewChunkedUploadReader creates a reader that handles large uploads efficiently
func NewChunkedUploadReader(r io.Reader, size int64) *ChunkedUploadReader {
	return &ChunkedUploadReader{
		reader:    r,
		size:      size,
		chunkSize: 1024 * 1024, // 1MB chunks
		chunks:    make(map[int64][]byte),
		position:  0,
	}
}

// Read implements io.Reader
func (c *ChunkedUploadReader) Read(p []byte) (n int, err error) {
	if c.position >= c.size {
		return 0, io.EOF
	}

	remaining := c.size - c.position
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	totalRead := 0
	for totalRead < len(p) {
		chunkIndex := c.position / c.chunkSize
		chunkOffset := c.position % c.chunkSize
		
		// Get or load the chunk
		chunk, err := c.getChunk(chunkIndex)
		if err != nil {
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, err
		}
		
		// Read from the chunk
		toCopy := int64(len(p) - totalRead)
		if toCopy > int64(len(chunk))-chunkOffset {
			toCopy = int64(len(chunk)) - chunkOffset
		}
		
		copy(p[totalRead:], chunk[chunkOffset:chunkOffset+toCopy])
		totalRead += int(toCopy)
		c.position += toCopy
	}

	return totalRead, nil
}

// Seek implements io.Seeker
func (c *ChunkedUploadReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = c.position + offset
	case io.SeekEnd:
		newPos = c.size + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newPos < 0 {
		return 0, fmt.Errorf("negative position: %d", newPos)
	}
	if newPos > c.size {
		newPos = c.size
	}

	c.position = newPos
	return newPos, nil
}

// getChunk loads a chunk if not already cached
func (c *ChunkedUploadReader) getChunk(index int64) ([]byte, error) {
	c.mu.RLock()
	if chunk, ok := c.chunks[index]; ok {
		c.mu.RUnlock()
		return chunk, nil
	}
	c.mu.RUnlock()

	// Need to load the chunk
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if chunk, ok := c.chunks[index]; ok {
		return chunk, nil
	}

	// Calculate how much to read
	startPos := index * c.chunkSize
	endPos := startPos + c.chunkSize
	if endPos > c.size {
		endPos = c.size
	}
	chunkSize := endPos - startPos

	// Read the chunk data
	chunk := make([]byte, chunkSize)
	readPos := 0
	for readPos < len(chunk) {
		n, err := c.reader.Read(chunk[readPos:])
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read chunk %d: %w", index, err)
		}
		readPos += n
		if err == io.EOF && readPos < len(chunk) {
			return nil, io.ErrUnexpectedEOF
		}
	}

	// Cache the chunk
	c.chunks[index] = chunk
	
	// Log progress for large uploads
	if c.size > 100*1024*1024 { // Log for uploads > 100MB
		cachedSize := int64(len(c.chunks)) * c.chunkSize
		logrus.WithFields(logrus.Fields{
			"chunkIndex":   index,
			"cachedChunks": len(c.chunks),
			"cachedMB":     cachedSize / 1024 / 1024,
			"totalMB":      c.size / 1024 / 1024,
		}).Debug("Chunk loaded for upload")
	}

	return chunk, nil
}

// Close implements io.Closer
func (c *ChunkedUploadReader) Close() error {
	c.chunks = nil // Free memory
	if closer, ok := c.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}