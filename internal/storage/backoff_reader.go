package storage

import (
	"io"
	"sync/atomic"
	"time"
)

// BackoffReader implements exponential backoff for degrading connections
type BackoffReader struct {
	reader        io.Reader
	lastReadTime  time.Time
	slowReads     int32
	backoffMs     int64
	totalBytes    int64
	recentBytes   int64
	recentStart   time.Time
}

// NewBackoffReader creates a reader that backs off when performance degrades
func NewBackoffReader(r io.Reader) *BackoffReader {
	return &BackoffReader{
		reader:      r,
		lastReadTime: time.Now(),
		recentStart: time.Now(),
		backoffMs:   10, // Start with 10ms
	}
}

func (br *BackoffReader) Read(p []byte) (int, error) {
	// Measure recent throughput
	if time.Since(br.recentStart) > 5*time.Second {
		recentRate := float64(br.recentBytes) / time.Since(br.recentStart).Seconds()
		if recentRate < 50*1024 { // Less than 50KB/s
			// Very slow, increase backoff
			atomic.AddInt64(&br.backoffMs, 10)
			if br.backoffMs > 1000 {
				br.backoffMs = 1000 // Cap at 1 second
			}
		} else if recentRate > 200*1024 { // More than 200KB/s
			// Good speed, reduce backoff
			atomic.AddInt64(&br.backoffMs, -5)
			if br.backoffMs < 10 {
				br.backoffMs = 10
			}
		}
		br.recentBytes = 0
		br.recentStart = time.Now()
	}

	// Apply backoff
	if br.backoffMs > 10 {
		time.Sleep(time.Duration(atomic.LoadInt64(&br.backoffMs)) * time.Millisecond)
	}

	// Limit read size for degraded connections
	readSize := len(p)
	if br.slowReads > 5 && readSize > 16*1024 {
		readSize = 16 * 1024 // 16KB max when slow
	}

	start := time.Now()
	n, err := br.reader.Read(p[:readSize])
	elapsed := time.Since(start)

	if n > 0 {
		atomic.AddInt64(&br.totalBytes, int64(n))
		atomic.AddInt64(&br.recentBytes, int64(n))
		
		// Track slow reads
		if elapsed > 2*time.Second {
			atomic.AddInt32(&br.slowReads, 1)
		} else if elapsed < 100*time.Millisecond {
			// Fast read, reduce slow counter
			if br.slowReads > 0 {
				atomic.AddInt32(&br.slowReads, -1)
			}
		}
	}

	br.lastReadTime = time.Now()
	return n, err
}