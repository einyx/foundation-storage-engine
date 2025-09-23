package storage

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestAWSChunkDecoder(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "single chunk with trailing CRLF",
			input:    "5;chunk-signature=abc\r\nhello\r\n0;chunk-signature=xyz\r\n\r\n",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "single chunk without trailing CRLF on last chunk",
			input:    "5;chunk-signature=abc\r\nhello",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "multiple chunks",
			input:    "5;chunk-signature=abc\r\nhello\r\n6;chunk-signature=def\r\n world\r\n0;chunk-signature=xyz\r\n\r\n",
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "chunk with simple hex format",
			input:    "5\r\nhello\r\n0\r\n\r\n",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "large chunk matching file size (like JSON files)",
			input:    "1a;chunk-signature=abc\r\n{\"key\":\"value\",\"test\":123}",
			expected: "{\"key\":\"value\",\"test\":123}",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := NewAWSChunkDecoder(bytes.NewReader([]byte(tt.input)))

			// Read all data
			var result bytes.Buffer
			_, err := io.Copy(&result, decoder)

			if (err != nil && err != io.EOF) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got := result.String(); got != tt.expected {
				t.Errorf("Read() got = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAWSChunkDecoderRealWorldCase(t *testing.T) {
	// Test case mimicking the actual truncated JSON file
	jsonContent := `{"format-version":2,"table-uuid":"test-uuid","location":"s3a://test","last-sequence-number":1}`
	chunkSize := len(jsonContent)

	// Create chunked input without trailing CRLF (as seen in the real files)
	input := fmt.Sprintf("%x;chunk-signature=501d7bfa23f30a4ec135bcf6634418b8fc29a15c386d0c6280a34685b096c6c8\r\n%s", chunkSize, jsonContent)

	decoder := NewAWSChunkDecoder(bytes.NewReader([]byte(input)))

	// Read all data
	var result bytes.Buffer
	_, err := io.Copy(&result, decoder)
	if err != nil && err != io.EOF {
		t.Fatalf("Unexpected error: %v", err)
	}

	if got := result.String(); got != jsonContent {
		t.Errorf("Failed to decode real-world case\nGot:  %q\nWant: %q", got, jsonContent)
	}
}
