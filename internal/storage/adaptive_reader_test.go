package storage

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestNewAdaptiveReader(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	if adaptiveReader == nil {
		t.Fatal("NewAdaptiveReader returned nil")
	}
	
	if adaptiveReader.reader != reader {
		t.Error("Underlying reader not set correctly")
	}
	
	if adaptiveReader.minReadSize != 16*1024 {
		t.Errorf("Expected minReadSize 16KB, got %d", adaptiveReader.minReadSize)
	}
	
	if adaptiveReader.maxReadSize != 256*1024 {
		t.Errorf("Expected maxReadSize 256KB, got %d", adaptiveReader.maxReadSize)
	}
	
	if adaptiveReader.targetRate != 10*1024*1024 {
		t.Errorf("Expected targetRate 10MB/s, got %f", adaptiveReader.targetRate)
	}
	
	if !adaptiveReader.pacingEnabled {
		t.Error("Expected pacing to be enabled by default")
	}
	
	if adaptiveReader.currentRate != 0 {
		t.Errorf("Expected initial currentRate 0, got %f", adaptiveReader.currentRate)
	}
}

func TestAdaptiveReader_Read(t *testing.T) {
	data := []byte("Hello, World! This is a test message for adaptive reading.")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// Read data
	buffer := make([]byte, len(data))
	n, err := adaptiveReader.Read(buffer)
	
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	
	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}
	
	if !bytes.Equal(buffer[:n], data) {
		t.Errorf("Read data doesn't match original")
	}
	
	// Verify stats were updated
	if adaptiveReader.bytesRead != int64(len(data)) {
		t.Errorf("Expected bytesRead %d, got %d", len(data), adaptiveReader.bytesRead)
	}
	
	// Add small delay to ensure time calculation
	time.Sleep(time.Millisecond)
	
	if adaptiveReader.currentRate < 0 {
		t.Error("Expected currentRate to be non-negative")
	}
}

func TestAdaptiveReader_Read_EOF(t *testing.T) {
	data := []byte("test")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// Read all data
	buffer := make([]byte, len(data))
	n, err := adaptiveReader.Read(buffer)
	
	if err != nil {
		t.Fatalf("First read failed: %v", err)
	}
	
	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}
	
	// Try to read more - should get EOF
	buffer2 := make([]byte, 10)
	n2, err := adaptiveReader.Read(buffer2)
	
	if err != io.EOF {
		t.Errorf("Expected EOF, got: %v", err)
	}
	
	if n2 != 0 {
		t.Errorf("Expected 0 bytes on EOF, got %d", n2)
	}
}

func TestAdaptiveReader_Read_EmptyBuffer(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// Read with empty buffer
	buffer := make([]byte, 0)
	n, err := adaptiveReader.Read(buffer)
	
	if err != nil {
		t.Fatalf("Read with empty buffer failed: %v", err)
	}
	
	if n != 0 {
		t.Errorf("Expected 0 bytes read with empty buffer, got %d", n)
	}
	
	// Verify stats weren't affected
	if adaptiveReader.bytesRead != 0 {
		t.Errorf("Expected bytesRead 0, got %d", adaptiveReader.bytesRead)
	}
}

func TestAdaptiveReader_GetStats(t *testing.T) {
	data := []byte("test data for stats")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// Read some data
	buffer := make([]byte, len(data))
	_, err := adaptiveReader.Read(buffer)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	
	// Add small delay to ensure time calculation
	time.Sleep(time.Millisecond)
	
	// Get stats
	bytesRead, currentRate := adaptiveReader.GetStats()
	
	if bytesRead != int64(len(data)) {
		t.Errorf("Expected bytesRead %d, got %d", len(data), bytesRead)
	}
	
	if currentRate < 0 {
		t.Error("Expected non-negative currentRate in stats")
	}
}

func TestAdaptiveReader_SetTargetRate(t *testing.T) {
	data := []byte("test")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	newTargetRate := 5.0 * 1024 * 1024 // 5MB/s
	adaptiveReader.SetTargetRate(newTargetRate)
	
	if adaptiveReader.targetRate != newTargetRate {
		t.Errorf("Expected targetRate %f, got %f", newTargetRate, adaptiveReader.targetRate)
	}
}

func TestAdaptiveReader_DisablePacing(t *testing.T) {
	data := []byte("test")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// Should start with pacing enabled
	if !adaptiveReader.pacingEnabled {
		t.Error("Expected pacing to be enabled initially")
	}
	
	adaptiveReader.DisablePacing()
	
	if adaptiveReader.pacingEnabled {
		t.Error("Expected pacing to be disabled after DisablePacing()")
	}
}

func TestAdaptiveReader_MultipleReads(t *testing.T) {
	data := []byte("This is a longer test message that will be read in multiple chunks to test the adaptive reading behavior.")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	var totalRead int
	var result []byte
	
	// Read in chunks
	for {
		buffer := make([]byte, 10) // Small buffer to force multiple reads
		n, err := adaptiveReader.Read(buffer)
		
		if err == io.EOF {
			break
		}
		
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		
		result = append(result, buffer[:n]...)
		totalRead += n
		
		// Small delay to allow time calculations
		time.Sleep(time.Millisecond)
	}
	
	if totalRead != len(data) {
		t.Errorf("Expected to read %d bytes total, read %d", len(data), totalRead)
	}
	
	if !bytes.Equal(result, data) {
		t.Error("Reconstructed data doesn't match original")
	}
	
	// Verify final stats
	if adaptiveReader.bytesRead != int64(len(data)) {
		t.Errorf("Expected final bytesRead %d, got %d", len(data), adaptiveReader.bytesRead)
	}
}

func TestAdaptiveReader_ConcurrentReads(t *testing.T) {
	// Test that multiple goroutines can safely access the adaptive reader
	data := []byte("concurrent test data")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// This test mainly ensures no race conditions occur
	// The actual read will be performed by the first goroutine to acquire the lock
	done := make(chan bool, 2)
	
	for i := 0; i < 2; i++ {
		go func() {
			defer func() { done <- true }()
			
			buffer := make([]byte, len(data))
			_, err := adaptiveReader.Read(buffer)
			// One will succeed, one might get EOF or partial read
			if err != nil && err != io.EOF {
				t.Errorf("Concurrent read failed: %v", err)
			}
		}()
	}
	
	// Wait for both goroutines
	<-done
	<-done
}

func TestAdaptiveReader_ZeroByteRead(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)
	
	adaptiveReader := NewAdaptiveReader(reader)
	
	// Test zero-byte read (should return immediately)
	buffer := make([]byte, 0)
	n, err := adaptiveReader.Read(buffer)
	
	if err != nil {
		t.Fatalf("Zero-byte read failed: %v", err)
	}
	
	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

func TestAdaptiveReader_ReadFromFailingReader(t *testing.T) {
	// Test with a reader that always returns an error
	failingReader := &failingReader{}
	
	adaptiveReader := NewAdaptiveReader(failingReader)
	
	buffer := make([]byte, 100)
	_, err := adaptiveReader.Read(buffer)
	
	if err == nil {
		t.Error("Expected error from failing reader")
	}
	
	if err != io.ErrUnexpectedEOF {
		t.Errorf("Expected io.ErrUnexpectedEOF error, got: %v", err)
	}
}

// failingReader always returns an error
type failingReader struct{}

func (f *failingReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// For more comprehensive error testing
type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestAdaptiveReader_ReadError(t *testing.T) {
	errorReader := &errorReader{}
	adaptiveReader := NewAdaptiveReader(errorReader)
	
	buffer := make([]byte, 100)
	_, err := adaptiveReader.Read(buffer)
	
	if err != io.ErrClosedPipe {
		t.Errorf("Expected io.ErrClosedPipe, got: %v", err)
	}
}

func BenchmarkAdaptiveReader_Read(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		adaptiveReader := NewAdaptiveReader(reader)
		
		buffer := make([]byte, len(data))
		_, err := adaptiveReader.Read(buffer)
		if err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}

func BenchmarkAdaptiveReader_SmallReads(b *testing.B) {
	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		adaptiveReader := NewAdaptiveReader(reader)
		
		// Read in small chunks
		buffer := make([]byte, 1024)
		for {
			_, err := adaptiveReader.Read(buffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatalf("Read failed: %v", err)
			}
		}
	}
}