package storage

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestNewTimeoutReader(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)
	timeout := 5 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	if timeoutReader == nil {
		t.Fatal("NewTimeoutReader returned nil")
	}

	if timeoutReader.reader != reader {
		t.Error("Underlying reader not set correctly")
	}

	if timeoutReader.timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, timeoutReader.timeout)
	}

	if len(timeoutReader.buffer) != 64*1024 {
		t.Errorf("Expected buffer size 64KB, got %d", len(timeoutReader.buffer))
	}

	if timeoutReader.bufferValid != 0 {
		t.Errorf("Expected initial bufferValid 0, got %d", timeoutReader.bufferValid)
	}
}

func TestTimeoutReader_Read_SmallData(t *testing.T) {
	data := []byte("Hello, World!")
	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	// Read all data at once
	buffer := make([]byte, len(data))
	n, err := timeoutReader.Read(buffer)

	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}

	if !bytes.Equal(buffer[:n], data) {
		t.Errorf("Read data doesn't match original")
	}
}

func TestTimeoutReader_Read_LargeData(t *testing.T) {
	// Create data larger than 16KB to test chunking
	data := make([]byte, 32*1024) // 32KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	// Read in one go - should be chunked internally
	buffer := make([]byte, len(data))
	n, err := timeoutReader.Read(buffer)

	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Should read up to 16KB in first read
	if n > 16*1024 {
		t.Errorf("Expected to read at most 16KB, read %d", n)
	}

	if n == 0 {
		t.Error("Expected to read some data")
	}

	if !bytes.Equal(buffer[:n], data[:n]) {
		t.Error("Read data doesn't match original")
	}
}

func TestTimeoutReader_Read_MultipleReads(t *testing.T) {
	data := []byte("This is a test message for multiple reads.")
	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	var result []byte
	buffer := make([]byte, 10) // Small buffer to force multiple reads

	for {
		n, err := timeoutReader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		result = append(result, buffer[:n]...)
	}

	if !bytes.Equal(result, data) {
		t.Error("Reconstructed data doesn't match original")
	}
}

func TestTimeoutReader_Read_EOF(t *testing.T) {
	data := []byte("test")
	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	// Read all data
	buffer := make([]byte, len(data))
	n, err := timeoutReader.Read(buffer)

	if err != nil {
		t.Fatalf("First read failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}

	// Try to read more - should get EOF
	buffer2 := make([]byte, 10)
	n2, err := timeoutReader.Read(buffer2)

	if err != io.EOF {
		t.Errorf("Expected EOF, got: %v", err)
	}

	if n2 != 0 {
		t.Errorf("Expected 0 bytes on EOF, got %d", n2)
	}
}

func TestTimeoutReader_Read_EmptyBuffer(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	// Read with empty buffer
	buffer := make([]byte, 0)
	n, err := timeoutReader.Read(buffer)

	if err != nil {
		t.Fatalf("Read with empty buffer failed: %v", err)
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes read with empty buffer, got %d", n)
	}
}

func TestTimeoutReader_BufferedData(t *testing.T) {
	// Test scenario where data is buffered from previous read
	data := []byte("1234567890abcdefghij") // 20 bytes
	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	// First read with small buffer (smaller than data)
	buffer1 := make([]byte, 5)
	n1, err := timeoutReader.Read(buffer1)

	if err != nil {
		t.Fatalf("First read failed: %v", err)
	}

	if n1 != 5 {
		t.Errorf("Expected to read 5 bytes, read %d", n1)
	}

	if !bytes.Equal(buffer1, data[:5]) {
		t.Error("First read data doesn't match")
	}

	// Second read should get more data
	buffer2 := make([]byte, 10)
	n2, err := timeoutReader.Read(buffer2)

	if err != nil {
		t.Fatalf("Second read failed: %v", err)
	}

	if n2 == 0 {
		t.Error("Expected to read some data in second read")
	}

	// Verify data continuity
	if !bytes.Equal(buffer2[:n2], data[5:5+n2]) {
		t.Error("Second read data doesn't match expected sequence")
	}
}

func TestTimeoutReader_Read_SmallBufferWithLargeData(t *testing.T) {
	// Test reading large data with very small buffer
	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(reader, timeout)

	// Read with very small buffer
	buffer := make([]byte, 3)
	var result []byte

	for {
		n, err := timeoutReader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		result = append(result, buffer[:n]...)
	}

	if !bytes.Equal(result, data) {
		t.Error("Reconstructed data doesn't match original")
	}
}

func TestTimeoutReader_ReadError(t *testing.T) {
	// Test with a reader that returns an error
	errorReader := &errorReader{}
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(errorReader, timeout)

	buffer := make([]byte, 100)
	_, err := timeoutReader.Read(buffer)

	if err != io.ErrClosedPipe {
		t.Errorf("Expected io.ErrClosedPipe, got: %v", err)
	}
}

func TestTimeoutReader_PartialReadWithError(t *testing.T) {
	// Test reader that returns some data then an error
	partialReader := &partialErrorReader{data: []byte("partial")}
	timeout := 1 * time.Second

	timeoutReader := NewTimeoutReader(partialReader, timeout)

	buffer := make([]byte, 100)
	n, err := timeoutReader.Read(buffer)

	// Should get the partial data without error
	if err != nil {
		t.Fatalf("First read failed: %v", err)
	}

	if n != 7 { // "partial" = 7 bytes
		t.Errorf("Expected to read 7 bytes, read %d", n)
	}

	if !bytes.Equal(buffer[:n], []byte("partial")) {
		t.Error("Partial data doesn't match")
	}

	// Second read should get the error
	n2, err := timeoutReader.Read(buffer)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("Expected io.ErrUnexpectedEOF on second read, got: %v", err)
	}

	if n2 != 0 {
		t.Errorf("Expected 0 bytes on error read, got %d", n2)
	}
}

func TestTimeoutReader_ZeroTimeout(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)

	timeoutReader := NewTimeoutReader(reader, 0) // Zero timeout

	buffer := make([]byte, len(data))
	n, err := timeoutReader.Read(buffer)

	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}
}

// partialErrorReader returns data once, then errors
type partialErrorReader struct {
	data []byte
	read bool
}

func (p *partialErrorReader) Read(buf []byte) (int, error) {
	if !p.read {
		p.read = true
		n := copy(buf, p.data)
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF
}

func BenchmarkTimeoutReader_Read(b *testing.B) {
	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	timeout := 5 * time.Second

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		timeoutReader := NewTimeoutReader(reader, timeout)

		buffer := make([]byte, len(data))
		_, err := timeoutReader.Read(buffer)
		if err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}

func BenchmarkTimeoutReader_SmallReads(b *testing.B) {
	data := make([]byte, 32*1024) // 32KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	timeout := 5 * time.Second

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		timeoutReader := NewTimeoutReader(reader, timeout)

		// Read in small chunks
		buffer := make([]byte, 1024)
		for {
			_, err := timeoutReader.Read(buffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatalf("Read failed: %v", err)
			}
		}
	}
}