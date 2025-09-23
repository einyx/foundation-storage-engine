package storage

import (
	"fmt"
	"io"
	"sync"
	"time"
	
	"github.com/sirupsen/logrus"
)

// ProxyAwareReader handles slow data from reverse proxies
// It reads data with progress tracking and timeout handling
type ProxyAwareReader struct {
	reader        io.Reader
	size          int64
	bytesRead     int64
	lastProgress  time.Time
	mu            sync.Mutex
	readTimeout   time.Duration
	minBytesPerSec int64
}

// NewProxyAwareReader creates a reader that handles slow proxies
func NewProxyAwareReader(r io.Reader, size int64) *ProxyAwareReader {
	return &ProxyAwareReader{
		reader:         r,
		size:           size,
		lastProgress:   time.Now(),
		readTimeout:    10 * time.Second, // Progress timeout
		minBytesPerSec: 1024,             // Minimum 1KB/s
	}
}

// Read implements io.Reader with progress tracking
func (p *ProxyAwareReader) Read(buf []byte) (int, error) {
	p.mu.Lock()
	startRead := time.Now()
	startBytes := p.bytesRead
	p.mu.Unlock()

	// Set a deadline for this read
	deadline := time.After(p.readTimeout)
	resultCh := make(chan struct {
		n   int
		err error
	}, 1)

	// Read in background
	go func() {
		n, err := p.reader.Read(buf)
		resultCh <- struct {
			n   int
			err error
		}{n, err}
	}()

	// Wait for read or timeout
	select {
	case result := <-resultCh:
		if result.n > 0 {
			p.mu.Lock()
			p.bytesRead += int64(result.n)
			p.lastProgress = time.Now()
			
			// Log progress every 10MB or 5 seconds
			if p.bytesRead%(10*1024*1024) == 0 || time.Since(startRead) > 5*time.Second {
				elapsed := time.Since(startRead)
				bytesPerSec := float64(result.n) / elapsed.Seconds()
				
				logrus.WithFields(logrus.Fields{
					"bytesRead":    p.bytesRead,
					"totalSize":    p.size,
					"progress":     fmt.Sprintf("%.1f%%", float64(p.bytesRead)/float64(p.size)*100),
					"bytesPerSec":  bytesPerSec,
					"mbPerSec":     bytesPerSec / 1024 / 1024,
				}).Info("Upload progress through proxy")
			}
			p.mu.Unlock()
		}
		
		return result.n, result.err
		
	case <-deadline:
		p.mu.Lock()
		bytesInPeriod := p.bytesRead - startBytes
		timeElapsed := time.Since(startRead)
		p.mu.Unlock()
		
		// If we made some progress, continue
		if bytesInPeriod > 0 {
			bytesPerSec := float64(bytesInPeriod) / timeElapsed.Seconds()
			logrus.WithFields(logrus.Fields{
				"bytesInPeriod": bytesInPeriod,
				"timeElapsed":   timeElapsed,
				"bytesPerSec":   bytesPerSec,
			}).Warn("Slow read from proxy, but making progress")
			
			// Try again with what we have
			return 0, nil
		}
		
		// No progress at all
		return 0, fmt.Errorf("proxy read timeout: no data received in %v", p.readTimeout)
	}
}

// Progress returns upload progress info
func (p *ProxyAwareReader) Progress() (bytesRead int64, totalSize int64, lastProgress time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bytesRead, p.size, p.lastProgress
}