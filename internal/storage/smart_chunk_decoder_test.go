package storage

import (
	"bytes"
	"io"
	"testing"
)

func TestSmartChunkDecoder_RawData(t *testing.T) {
	// Test case where client sends raw Iceberg AVRO data but declares chunked encoding
	rawData := `e size in bytes","field-id":501},{"name":"partition_spec_id","type":"int","doc":"Spec ID used to write","field-id":502}`
	
	decoder := NewSmartChunkDecoder(bytes.NewReader([]byte(rawData)))
	
	// Read all data
	result, err := io.ReadAll(decoder)
	
	if err != nil && err != io.EOF {
		t.Fatalf("Expected successful read of raw data, got error: %v", err)
	}
	
	if len(result) != len(rawData) {
		t.Fatalf("Expected to read %d bytes, got %d", len(rawData), len(result))
	}
	
	if string(result) != rawData {
		t.Fatalf("Data mismatch. Expected: %s, Got: %s", rawData, string(result))
	}
}

func TestSmartChunkDecoder_ValidChunkedData(t *testing.T) {
	// Test case with valid AWS chunked data
	// Format: hex-size;chunk-signature=sig\r\ndata\r\n
	chunkedData := "1a;chunk-signature=abc123\r\nThis is some chunked data.\r\n0;chunk-signature=xyz\r\n\r\n"
	
	decoder := NewSmartChunkDecoder(bytes.NewReader([]byte(chunkedData)))
	
	// Read all data
	result := make([]byte, 26) // Length of "This is some chunked data."
	n, err := io.ReadFull(decoder, result)
	
	if err != nil && err != io.EOF {
		t.Fatalf("Expected successful read of chunked data, got error: %v", err)
	}
	
	if n != 26 {
		t.Fatalf("Expected to read 26 bytes, got %d", n)
	}
	
	expected := "This is some chunked data."
	if string(result) != expected {
		t.Fatalf("Data mismatch. Expected: %s, Got: %s", expected, string(result))
	}
}

func TestSmartChunkDecoder_IsValidChunkHeader(t *testing.T) {
	decoder := &SmartChunkDecoder{}
	
	tests := []struct {
		input    string
		expected bool
		desc     string
	}{
		{"1a", true, "valid hex size"},
		{"1a;chunk-signature=abc123", true, "valid hex size with signature"},
		{"0", true, "valid zero size"},
		{"ff", true, "valid hex"},
		{"FF", true, "valid uppercase hex"},
		{"1234567890abcdef", true, "valid long hex"},
		{"12345678901234567", false, "too long (>16 chars)"},
		{`e size in bytes"`, false, "Iceberg JSON data"},
		{`{"field-id":501}`, false, "JSON object"},
		{"hello", false, "non-hex string"},
		{"1g", false, "invalid hex character"},
		{"", false, "empty string"},
		{"1a;", true, "hex with semicolon but no signature"},
	}
	
	for _, tt := range tests {
		result := decoder.isValidChunkHeader(tt.input)
		if result != tt.expected {
			t.Errorf("isValidChunkHeader(%q) = %v, expected %v (%s)", 
				tt.input, result, tt.expected, tt.desc)
		}
	}
}