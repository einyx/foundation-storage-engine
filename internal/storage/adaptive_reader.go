package storage

import (
	"io"
	"sync"
	"time"
)

// AdaptiveReader implements flow control to prevent buffer bloat
type AdaptiveReader struct {
	reader io.Reader
	
	// Flow control
	bytesRead      int64
	startTime      time.Time
	lastReadTime   time.Time
	
	// Adaptive buffering
	currentRate    float64 // bytes per second
	targetRate     float64 // desired bytes per second
	
	// Pacing
	pacingEnabled  bool
	minReadSize    int
	maxReadSize    int
	
	mu sync.Mutex
}

// NewAdaptiveReader creates a reader that adapts to network conditions
func NewAdaptiveReader(r io.Reader) *AdaptiveReader {
	return &AdaptiveReader{
		reader:        r,
		startTime:     time.Now(),
		lastReadTime:  time.Now(),
		minReadSize:   16 * 1024,   // 16KB minimum
		maxReadSize:   256 * 1024,  // 256KB maximum
		targetRate:    10 * 1024 * 1024, // 10MB/s target
		pacingEnabled: true,
	}
}

func (ar *AdaptiveReader) Read(p []byte) (int, error) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	
	// Calculate current rate
	elapsed := time.Since(ar.startTime).Seconds()
	if elapsed > 0 {
		ar.currentRate = float64(ar.bytesRead) / elapsed
	}
	
	// Determine read size based on performance
	readSize := len(p)
	
	if ar.pacingEnabled && ar.bytesRead > 10*1024*1024 { // After 10MB
		// Slow down if we're going too fast (causing buffer bloat)
		if ar.currentRate > ar.targetRate*1.5 {
			// Reduce read size
			readSize = ar.minReadSize
			
			// Add small delay to pace the transfer
			delay := time.Duration(float64(readSize) / ar.targetRate * float64(time.Second))
			time.Sleep(delay / 2) // Half delay to maintain some speed
		} else if ar.currentRate < ar.targetRate*0.5 {
			// Speed up if we're too slow
			if readSize < ar.maxReadSize {
				readSize = readSize * 2
				if readSize > ar.maxReadSize {
					readSize = ar.maxReadSize
				}
			}
		}
	}
	
	// Limit read size
	if readSize > len(p) {
		readSize = len(p)
	}
	
	// Perform the read
	n, err := ar.reader.Read(p[:readSize])
	
	if n > 0 {
		ar.bytesRead += int64(n)
		ar.lastReadTime = time.Now()
	}
	
	return n, err
}

// GetStats returns current transfer statistics
func (ar *AdaptiveReader) GetStats() (bytesRead int64, rate float64) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	
	return ar.bytesRead, ar.currentRate
}

// SetTargetRate sets the desired transfer rate in bytes per second
func (ar *AdaptiveReader) SetTargetRate(rate float64) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	
	ar.targetRate = rate
}

// DisablePacing disables rate limiting (for testing)
func (ar *AdaptiveReader) DisablePacing() {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	
	ar.pacingEnabled = false
}