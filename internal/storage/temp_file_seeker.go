package storage

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"time"
	
	"github.com/sirupsen/logrus"
)

// TempFileSeeker provides a seekable interface by using a temporary file
// This is used for large uploads that need full seek capability
type TempFileSeeker struct {
	reader       io.Reader
	size         int64
	tempFile     *os.File
	writeComplete bool
	writeMu      sync.Mutex
	readMu       sync.Mutex
	bytesWritten int64
	lastLog      time.Time
}

// NewTempFileSeeker creates a seekable reader using a temp file
func NewTempFileSeeker(r io.Reader, size int64) (*TempFileSeeker, error) {
	tempFile, err := ioutil.TempFile("", "upload-part-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	seeker := &TempFileSeeker{
		reader:   r,
		size:     size,
		tempFile: tempFile,
		lastLog:  time.Now(),
	}

	// Start writing data to temp file in background
	go seeker.writeToTempFile()

	return seeker, nil
}

// writeToTempFile writes data from reader to temp file
func (t *TempFileSeeker) writeToTempFile() {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	buf := make([]byte, 1024*1024) // 1MB buffer for efficient copying
	
	for {
		n, err := t.reader.Read(buf)
		if n > 0 {
			written, writeErr := t.tempFile.Write(buf[:n])
			if writeErr != nil {
				logrus.WithError(writeErr).Error("Failed to write to temp file")
				return
			}
			t.bytesWritten += int64(written)
			
			// Log progress every 100MB or 5 seconds
			if t.bytesWritten%(100*1024*1024) == 0 || time.Since(t.lastLog) > 5*time.Second {
				logrus.WithFields(logrus.Fields{
					"bytesWritten": t.bytesWritten,
					"writtenMB":    t.bytesWritten / 1024 / 1024,
					"totalMB":      t.size / 1024 / 1024,
					"progress":     fmt.Sprintf("%.1f%%", float64(t.bytesWritten)/float64(t.size)*100),
				}).Info("Writing large part to temp file")
				t.lastLog = time.Now()
			}
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			logrus.WithError(err).Error("Error reading from source")
			return
		}
	}
	
	t.writeComplete = true
	logrus.WithFields(logrus.Fields{
		"totalBytes": t.bytesWritten,
		"totalMB":    t.bytesWritten / 1024 / 1024,
		"tempFile":   t.tempFile.Name(),
	}).Info("Completed writing part to temp file")
}

// Read implements io.Reader
func (t *TempFileSeeker) Read(p []byte) (n int, err error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	// Wait for enough data to be written
	currentPos, _ := t.tempFile.Seek(0, io.SeekCurrent)
	for currentPos+int64(len(p)) > t.bytesWritten && !t.writeComplete {
		t.readMu.Unlock()
		time.Sleep(10 * time.Millisecond)
		t.readMu.Lock()
	}

	return t.tempFile.Read(p)
}

// Seek implements io.Seeker
func (t *TempFileSeeker) Seek(offset int64, whence int) (int64, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	// For seeking to end, wait for write to complete
	if whence == io.SeekEnd {
		for !t.writeComplete {
			t.readMu.Unlock()
			time.Sleep(10 * time.Millisecond)
			t.readMu.Lock()
		}
	}

	// For seeking to a specific position, wait for that much data
	if whence == io.SeekStart && offset > t.bytesWritten && !t.writeComplete {
		for offset > t.bytesWritten && !t.writeComplete {
			t.readMu.Unlock()
			time.Sleep(10 * time.Millisecond)
			t.readMu.Lock()
		}
	}

	return t.tempFile.Seek(offset, whence)
}

// Close cleans up the temp file
func (t *TempFileSeeker) Close() error {
	t.tempFile.Close()
	os.Remove(t.tempFile.Name())
	return nil
}

// Len returns the size if known (for AWS SDK)
func (t *TempFileSeeker) Len() int {
	if t.size > 0 {
		return int(t.size)
	}
	return int(t.bytesWritten)
}