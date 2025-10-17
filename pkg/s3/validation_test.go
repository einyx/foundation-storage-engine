package s3

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateBucketName(t *testing.T) {
	tests := []struct {
		name        string
		bucket      string
		expectError bool
		errorMsg    string
	}{
		// Valid bucket names
		{name: "valid simple name", bucket: "mybucket", expectError: false},
		{name: "valid with numbers", bucket: "mybucket123", expectError: false},
		{name: "valid with hyphens", bucket: "my-bucket-name", expectError: false},
		{name: "minimum length", bucket: "abc", expectError: false},
		{name: "maximum length", bucket: strings.Repeat("a", 63), expectError: false},

		// Invalid bucket names
		{name: "empty bucket", bucket: "", expectError: true, errorMsg: "path cannot be empty"},
		{name: "too short", bucket: "ab", expectError: true, errorMsg: "bucket name must be between"},
		{name: "too long", bucket: strings.Repeat("a", 64), expectError: true, errorMsg: "bucket name must be between"},
		{name: "uppercase letters", bucket: "MyBucket", expectError: true, errorMsg: "bucket name must contain only lowercase"},
		{name: "underscore", bucket: "my_bucket", expectError: true, errorMsg: "bucket name must contain only lowercase"},
		{name: "starts with hyphen", bucket: "-mybucket", expectError: true, errorMsg: "bucket name must contain only lowercase"},
		{name: "ends with hyphen", bucket: "mybucket-", expectError: true, errorMsg: "bucket name must contain only lowercase"},
		{name: "consecutive hyphens", bucket: "my--bucket", expectError: true, errorMsg: "bucket name cannot contain consecutive"},
		{name: "consecutive dots", bucket: "my..bucket", expectError: true, errorMsg: "path contains traversal sequences"},
		{name: "IP address format", bucket: "192.168.1.1", expectError: true, errorMsg: "bucket name cannot be an IP address"},
		{name: "starts with number ending with hyphen", bucket: "1bucket-", expectError: true, errorMsg: "bucket name must contain only lowercase"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucketName(tt.bucket)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for bucket '%s', but got none", tt.bucket)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for bucket '%s', but got: %s", tt.bucket, err.Error())
				}
			}
		})
	}
}

func TestValidateObjectKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		expectError bool
		errorMsg    string
	}{
		// Valid object keys
		{name: "simple file name", key: "file.txt", expectError: false},
		{name: "path with slashes", key: "folder/subfolder/file.txt", expectError: false},
		{name: "special characters", key: "file-name_with.special@chars.txt", expectError: false},
		{name: "unicode characters", key: "файл.txt", expectError: false},
		{name: "spaces", key: "file with spaces.txt", expectError: false},

		// Invalid object keys
		{name: "empty key", key: "", expectError: true, errorMsg: "path cannot be empty"},
		{name: "too long", key: strings.Repeat("a", 1025), expectError: true, errorMsg: "object key cannot exceed"},
		{name: "path traversal ../ ", key: "folder/../file.txt", expectError: true, errorMsg: "path contains traversal sequences"},
		{name: "path traversal ..\\ ", key: "folder\\..\\file.txt", expectError: true, errorMsg: "path contains traversal sequences"},
		{name: "null byte", key: "file\x00.txt", expectError: true, errorMsg: "path contains invalid characters"},
		{name: "control character", key: "file\x01.txt", expectError: true, errorMsg: "path contains invalid characters"},
		{name: "dangerous path /etc/", key: "/etc/passwd", expectError: true, errorMsg: "absolute paths not allowed"},
		{name: "dangerous path windows", key: "\\windows\\system32\\file", expectError: true, errorMsg: "path contains invalid characters"},
		{name: "invalid UTF-8", key: string([]byte{0xff, 0xfe, 0xfd}), expectError: true, errorMsg: "object key contains invalid UTF-8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateObjectKey(tt.key)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for key '%s', but got none", tt.key)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for key '%s', but got: %s", tt.key, err.Error())
				}
			}
		})
	}
}

func TestValidateMetadata(t *testing.T) {
	tests := []struct {
		name        string
		metadata    map[string]string
		expectError bool
		errorMsg    string
	}{
		// Valid metadata
		{name: "nil metadata", metadata: nil, expectError: false},
		{name: "empty metadata", metadata: map[string]string{}, expectError: false},
		{name: "valid simple", metadata: map[string]string{"key1": "value1", "key2": "value2"}, expectError: false},
		{name: "valid with hyphens", metadata: map[string]string{"my-key": "my-value"}, expectError: false},
		{name: "valid with underscores", metadata: map[string]string{"my_key": "my_value"}, expectError: false},

		// Invalid metadata
		{
			name:        "invalid key characters",
			metadata:    map[string]string{"key with spaces": "value"},
			expectError: true,
			errorMsg:    "metadata key can only contain",
		},
		{
			name:        "key too long",
			metadata:    map[string]string{strings.Repeat("a", 129): "value"},
			expectError: true,
			errorMsg:    "metadata key cannot exceed",
		},
		{
			name:        "value too long",
			metadata:    map[string]string{"key": strings.Repeat("a", 257)},
			expectError: true,
			errorMsg:    "metadata value cannot exceed",
		},
		{
			name:        "total size too large",
			metadata:    createLargeMetadata(),
			expectError: true,
			errorMsg:    "total metadata size cannot exceed",
		},
		{
			name:        "value with control character",
			metadata:    map[string]string{"key": "value\x01"},
			expectError: true,
			errorMsg:    "metadata value contains invalid control character",
		},
		{
			name:        "invalid UTF-8 value",
			metadata:    map[string]string{"key": string([]byte{0xff, 0xfe})},
			expectError: true,
			errorMsg:    "metadata value contains invalid UTF-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMetadata(tt.metadata)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for metadata, but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for metadata, but got: %s", err.Error())
				}
			}
		})
	}
}

func createLargeMetadata() map[string]string {
	metadata := make(map[string]string)
	// Create metadata that exceeds 2KB total size
	// Using shorter values to avoid hitting individual value length limit first
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := strings.Repeat("v", 50) // Total: ~50 * (6 + 50) = 2800 bytes > 2048
		metadata[key] = value
	}
	return metadata
}

func TestValidatePartNumber(t *testing.T) {
	tests := []struct {
		name           string
		partNumberStr  string
		expectedNumber int
		expectError    bool
		errorMsg       string
	}{
		// Valid part numbers
		{name: "valid part 1", partNumberStr: "1", expectedNumber: 1, expectError: false},
		{name: "valid part 5000", partNumberStr: "5000", expectedNumber: 5000, expectError: false},
		{name: "valid part 10000", partNumberStr: "10000", expectedNumber: 10000, expectError: false},

		// Invalid part numbers
		{name: "empty", partNumberStr: "", expectError: true, errorMsg: "part number is required"},
		{name: "non-numeric", partNumberStr: "abc", expectError: true, errorMsg: "part number must be a valid integer"},
		{name: "zero", partNumberStr: "0", expectError: true, errorMsg: "part number must be between 1 and"},
		{name: "negative", partNumberStr: "-1", expectError: true, errorMsg: "part number must be between 1 and"},
		{name: "too large", partNumberStr: "10001", expectError: true, errorMsg: "part number must be between 1 and"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			partNumber, err := ValidatePartNumber(tt.partNumberStr)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for part number '%s', but got none", tt.partNumberStr)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for part number '%s', but got: %s", tt.partNumberStr, err.Error())
					return
				}
				if partNumber != tt.expectedNumber {
					t.Errorf("Expected part number %d, got %d", tt.expectedNumber, partNumber)
				}
			}
		})
	}
}

func TestValidateUploadID(t *testing.T) {
	tests := []struct {
		name        string
		uploadID    string
		expectError bool
		errorMsg    string
	}{
		// Valid upload IDs
		{name: "valid base64-like", uploadID: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.", expectError: false},
		{name: "typical upload ID", uploadID: "2~nwwzudgkmYF-IWQhoKJlTuS7cZKxLyxONKNTOH-INvWNTsOZxv0BJ3GYnbX", expectError: false},

		// Invalid upload IDs
		{name: "empty", uploadID: "", expectError: true, errorMsg: "upload ID cannot be empty"},
		{name: "too short", uploadID: "short", expectError: true, errorMsg: "upload ID has invalid length"},
		{name: "too long", uploadID: strings.Repeat("a", 1025), expectError: true, errorMsg: "upload ID has invalid length"},
		{name: "invalid characters", uploadID: "upload-id-with-@-symbols", expectError: true, errorMsg: "upload ID contains invalid characters"},
		{name: "with spaces", uploadID: "upload id with spaces", expectError: true, errorMsg: "upload ID contains invalid characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUploadID(tt.uploadID)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for upload ID '%s', but got none", tt.uploadID)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for upload ID '%s', but got: %s", tt.uploadID, err.Error())
				}
			}
		})
	}
}

func TestValidateMaxKeys(t *testing.T) {
	tests := []struct {
		name            string
		maxKeysStr      string
		expectedMaxKeys int
		expectError     bool
		errorMsg        string
	}{
		// Valid max-keys
		{name: "empty (default)", maxKeysStr: "", expectedMaxKeys: 1000, expectError: false},
		{name: "valid number", maxKeysStr: "100", expectedMaxKeys: 100, expectError: false},
		{name: "zero", maxKeysStr: "0", expectedMaxKeys: 0, expectError: false},
		{name: "maximum allowed", maxKeysStr: "1000", expectedMaxKeys: 1000, expectError: false},
		{name: "above maximum", maxKeysStr: "2000", expectedMaxKeys: 1000, expectError: false}, // Capped at max

		// Invalid max-keys
		{name: "non-numeric", maxKeysStr: "abc", expectError: true, errorMsg: "max-keys must be a valid integer"},
		{name: "negative", maxKeysStr: "-1", expectError: true, errorMsg: "max-keys cannot be negative"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxKeys, err := ValidateMaxKeys(tt.maxKeysStr)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for max-keys '%s', but got none", tt.maxKeysStr)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for max-keys '%s', but got: %s", tt.maxKeysStr, err.Error())
					return
				}
				if maxKeys != tt.expectedMaxKeys {
					t.Errorf("Expected max-keys %d, got %d", tt.expectedMaxKeys, maxKeys)
				}
			}
		})
	}
}

func TestValidateCopySource(t *testing.T) {
	tests := []struct {
		name           string
		copySource     string
		expectedBucket string
		expectedKey    string
		expectError    bool
		errorMsg       string
	}{
		// Valid copy sources
		{name: "simple copy", copySource: "mybucket/myfile.txt", expectedBucket: "mybucket", expectedKey: "myfile.txt", expectError: false},
		{name: "with leading slash", copySource: "/mybucket/folder/file.txt", expectedBucket: "mybucket", expectedKey: "folder/file.txt", expectError: false},
		{name: "URL encoded", copySource: "mybucket/my%20file.txt", expectedBucket: "mybucket", expectedKey: "my file.txt", expectError: false},

		// Invalid copy sources
		{name: "empty", copySource: "", expectError: true, errorMsg: "copy source cannot be empty"},
		{name: "invalid format", copySource: "just-a-bucket", expectError: true, errorMsg: "copy source must be in format bucket/key"},
		{name: "invalid bucket name", copySource: "Invalid-Bucket/file.txt", expectError: true, errorMsg: "invalid source bucket"},
		{name: "invalid key", copySource: "mybucket/../etc/passwd", expectError: true, errorMsg: "invalid source key"},
		{name: "invalid URL encoding", copySource: "mybucket/file%ZZ.txt", expectError: true, errorMsg: "invalid URL encoding"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key, err := ValidateCopySource(tt.copySource)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for copy source '%s', but got none", tt.copySource)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for copy source '%s', but got: %s", tt.copySource, err.Error())
					return
				}
				if bucket != tt.expectedBucket {
					t.Errorf("Expected bucket '%s', got '%s'", tt.expectedBucket, bucket)
				}
				if key != tt.expectedKey {
					t.Errorf("Expected key '%s', got '%s'", tt.expectedKey, key)
				}
			}
		})
	}
}

func TestValidateContentLength(t *testing.T) {
	tests := []struct {
		name             string
		contentLengthStr string
		expectedLength   int64
		expectError      bool
		errorMsg         string
	}{
		// Valid content lengths
		{name: "empty (optional)", contentLengthStr: "", expectedLength: 0, expectError: false},
		{name: "zero", contentLengthStr: "0", expectedLength: 0, expectError: false},
		{name: "valid size", contentLengthStr: "1024", expectedLength: 1024, expectError: false},
		{name: "large valid size", contentLengthStr: "1073741824", expectedLength: 1073741824, expectError: false}, // 1GB

		// Invalid content lengths
		{name: "non-numeric", contentLengthStr: "abc", expectError: true, errorMsg: "Content-Length must be a valid integer"},
		{name: "negative", contentLengthStr: "-1", expectError: true, errorMsg: "Content-Length cannot be negative"},
		{name: "too large", contentLengthStr: "5497558138881", expectError: true, errorMsg: "Content-Length cannot exceed"}, // > 5TB
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, err := ValidateContentLength(tt.contentLengthStr)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for content length '%s', but got none", tt.contentLengthStr)
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for content length '%s', but got: %s", tt.contentLengthStr, err.Error())
					return
				}
				if length != tt.expectedLength {
					t.Errorf("Expected content length %d, got %d", tt.expectedLength, length)
				}
			}
		})
	}
}

func TestValidateDeleteObjects(t *testing.T) {
	tests := []struct {
		name        string
		objects     []string
		expectError bool
		errorMsg    string
	}{
		// Valid delete requests
		{name: "single object", objects: []string{"file.txt"}, expectError: false},
		{name: "multiple objects", objects: []string{"file1.txt", "folder/file2.txt", "file3.txt"}, expectError: false},
		{name: "maximum objects", objects: make([]string, 1000), expectError: false},

		// Invalid delete requests
		{name: "empty list", objects: []string{}, expectError: true, errorMsg: "delete request must contain at least one object"},
		{name: "too many objects", objects: make([]string, 1001), expectError: true, errorMsg: "cannot delete more than"},
		{name: "invalid object key", objects: []string{"valid.txt", "../etc/passwd"}, expectError: true, errorMsg: "invalid object key at index"},
	}

	// Initialize valid object keys for the "maximum objects" test
	for i := range tests[2].objects {
		tests[2].objects[i] = "file" + string(rune('0'+i%10)) + ".txt"
	}

	// Initialize object keys for the "too many objects" test
	for i := range tests[4].objects {
		tests[4].objects[i] = "file" + string(rune('0'+i%10)) + ".txt"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDeleteObjects(tt.objects)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for delete objects, but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error for delete objects, but got: %s", err.Error())
				}
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := &ValidationError{
		Field:   "bucket",
		Value:   "Invalid-Bucket",
		Message: "bucket name must contain only lowercase letters",
	}

	expectedError := "validation error for bucket: bucket name must contain only lowercase letters (value: Invalid-Bucket)"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}
