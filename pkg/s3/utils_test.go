package s3

import (
	"testing"
)

func TestIsIcebergMetadata(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "metadata.json file",
			key:      "warehouse/table1/metadata/metadata.json",
			expected: true,
		},
		{
			name:     "versioned metadata file",
			key:      "warehouse/table1/metadata/v1.metadata.json",
			expected: true,
		},
		{
			name:     "version metadata file",
			key:      "warehouse/table1/metadata/version-hint.text",
			expected: true, // Version hint files are metadata
		},
		{
			name:     "snap file",
			key:      "warehouse/table1/metadata/snap-123456789.avro",
			expected: true, // This is metadata
		},
		{
			name:     "manifest list",
			key:      "warehouse/table1/metadata/snap-123456789-1-c87bfec7-d36c-4075-ad04-3dcb2ca0f2b5.avro",
			expected: true, // This is metadata
		},
		{
			name:     "regular data file",
			key:      "warehouse/table1/data/file1.parquet",
			expected: false,
		},
		{
			name:     "regular text file",
			key:      "warehouse/table1/readme.txt",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
		{
			name:     "metadata in filename but not path",
			key:      "warehouse/table1/data/metadata_backup.json",
			expected: false, // Not in metadata directory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIcebergMetadata(tt.key)
			if result != tt.expected {
				t.Errorf("isIcebergMetadata(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

func TestIsIcebergManifest(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "manifest avro file",
			key:      "warehouse/table1/metadata/c87bfec7-d36c-4075-ad04-3dcb2ca0f2b5.avro",
			expected: false, // Doesn't contain "manifest" or "snap-"
		},
		{
			name:     "manifest list file",
			key:      "warehouse/table1/metadata/snap-123456789-1-c87bfec7-d36c-4075-ad04-3dcb2ca0f2b5.avro",
			expected: true, // Contains "snap-"
		},
		{
			name:     "manifest named file",
			key:      "warehouse/table1/metadata/manifest-list.avro",
			expected: true, // Contains "manifest"
		},
		{
			name:     "data avro file not in metadata",
			key:      "warehouse/table1/data/file1.avro",
			expected: false,
		},
		{
			name:     "metadata json file",
			key:      "warehouse/table1/metadata/metadata.json",
			expected: false,
		},
		{
			name:     "regular parquet file",
			key:      "warehouse/table1/data/file1.parquet",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIcebergManifest(tt.key)
			if result != tt.expected {
				t.Errorf("isIcebergManifest(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

func TestIsIcebergData(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "parquet data file",
			key:      "warehouse/table1/data/file1.parquet",
			expected: true,
		},
		{
			name:     "orc data file",
			key:      "warehouse/table1/data/file1.orc",
			expected: true,
		},
		{
			name:     "avro data file in data directory",
			key:      "warehouse/table1/data/file1.avro",
			expected: true,
		},
		{
			name:     "nested data file",
			key:      "warehouse/table1/data/year=2023/month=12/file1.parquet",
			expected: true,
		},
		{
			name:     "metadata file",
			key:      "warehouse/table1/metadata/metadata.json",
			expected: false,
		},
		{
			name:     "avro manifest file",
			key:      "warehouse/table1/metadata/manifest1.avro",
			expected: false,
		},
		{
			name:     "regular text file",
			key:      "warehouse/table1/readme.txt",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIcebergData(tt.key)
			if result != tt.expected {
				t.Errorf("isIcebergData(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

func TestIsAvroFile(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "avro file",
			key:      "path/to/file.avro",
			expected: true,
		},
		{
			name:     "AVRO file uppercase",
			key:      "path/to/file.AVRO",
			expected: false, // Case-sensitive check
		},
		{
			name:     "mixed case avro",
			key:      "path/to/file.Avro",
			expected: false, // Case-sensitive check
		},
		{
			name:     "parquet file",
			key:      "path/to/file.parquet",
			expected: false,
		},
		{
			name:     "avro in filename but not extension",
			key:      "path/to/avro_file.txt",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
		{
			name:     "no extension",
			key:      "path/to/file",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAvroFile(tt.key)
			if result != tt.expected {
				t.Errorf("isAvroFile(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

func TestExtractTableName(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "simple table path",
			key:      "warehouse/customers/data/file1.parquet",
			expected: "customers", // Returns part before data directory
		},
		{
			name:     "table with metadata",
			key:      "warehouse/orders/metadata/metadata.json",
			expected: "orders", // Returns part before metadata directory
		},
		{
			name:     "nested partitioned data",
			key:      "warehouse/sales/data/year=2023/month=12/file1.parquet",
			expected: "sales", // Returns part before data directory
		},
		{
			name:     "table with underscore before metadata",
			key:      "warehouse/user_events/_metadata/snap-123.avro",
			expected: "user_events", // Found underscore prefix, returns previous part
		},
		{
			name:     "complex table name",
			key:      "data_warehouse/customer_orders_fact/data/file1.parquet",
			expected: "customer_orders_fact", // Returns part before data directory
		},
		{
			name:     "short path",
			key:      "table1/file.txt",
			expected: "table1", // Returns second-to-last part (only 2 parts)
		},
		{
			name:     "single level",
			key:      "file.txt",
			expected: "unknown", // Less than 2 parts
		},
		{
			name:     "empty key",
			key:      "",
			expected: "unknown", // Empty key
		},
		{
			name:     "root level file",
			key:      "/file.txt",
			expected: "", // Empty first part, returns second-to-last
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTableName(tt.key)
			if result != tt.expected {
				t.Errorf("extractTableName(%q) = %q, want %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestIsJavaSDKClient(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{
			name:      "Trino client",
			userAgent: "aws-sdk-java/2.30.12 md/io#sync md/http#Apache ua/2.1 os/Linux lang/java#23.0.2 app/Trino",
			expected:  true,
		},
		{
			name:      "Hive client",
			userAgent: "aws-sdk-java/1.12.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hive/3.1.2",
			expected:  true,
		},
		{
			name:      "Hadoop S3A client",
			userAgent: "aws-sdk-java/1.11.1026 Linux/5.4.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hadoop-s3a/3.3.4",
			expected:  true,
		},
		{
			name:      "Spark client",
			userAgent: "aws-sdk-java/2.20.0 Spark/3.4.0",
			expected:  true,
		},
		{
			name:      "case insensitive Trino",
			userAgent: "aws-sdk-java/2.30.12 APP/TRINO",
			expected:  true,
		},
		{
			name:      "case insensitive Hive",
			userAgent: "aws-sdk-java/1.12.0 HIVE/3.1.2",
			expected:  true,
		},
		{
			name:      "case insensitive Hadoop",
			userAgent: "aws-sdk-java/1.11.1026 HADOOP-s3a/3.3.4",
			expected:  true,
		},
		{
			name:      "S3A client",
			userAgent: "MyApp/1.0 s3a-client/2.0",
			expected:  true,
		},
		{
			name:      "generic Java SDK",
			userAgent: "aws-sdk-java/2.20.0 java/17.0.2",
			expected:  false,
		},
		{
			name:      "AWS CLI",
			userAgent: "aws-cli/2.0.0",
			expected:  false,
		},
		{
			name:      "browser client",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expected:  false,
		},
		{
			name:      "MinIO client",
			userAgent: "MinIO (linux; amd64) minio-go/v7.0.0",
			expected:  false,
		},
		{
			name:      "empty user agent",
			userAgent: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isJavaSDKClient(tt.userAgent)
			if result != tt.expected {
				t.Errorf("isJavaSDKClient(%q) = %v, want %v", tt.userAgent, result, tt.expected)
			}
		})
	}
}

func TestIsAWSCLIClient(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{
			name:      "AWS CLI v2",
			userAgent: "aws-cli/2.0.0 Python/3.8.0 Linux/5.4.0-74-generic source/x86_64.ubuntu.20",
			expected:  true,
		},
		{
			name:      "AWS CLI v1",
			userAgent: "aws-cli/1.18.69 Python/3.8.5 Linux/5.4.0-74-generic source/x86_64.ubuntu.20",
			expected:  true,
		},
		{
			name:      "case insensitive AWS CLI",
			userAgent: "AWS-CLI/2.0.0",
			expected:  true,
		},
		{
			name:      "Java SDK",
			userAgent: "aws-sdk-java/2.20.0",
			expected:  false,
		},
		{
			name:      "browser",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expected:  false,
		},
		{
			name:      "empty user agent",
			userAgent: "",
			expected:  false,
		},
		{
			name:      "CLI in different context",
			userAgent: "MyApp/1.0 (uses cli internally)",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAWSCLIClient(tt.userAgent)
			if result != tt.expected {
				t.Errorf("isAWSCLIClient(%q) = %v, want %v", tt.userAgent, result, tt.expected)
			}
		})
	}
}

func TestIsChunkedWithoutSize(t *testing.T) {
	tests := []struct {
		name             string
		size             int64
		transferEncoding string
		contentSha256    string
		expected         bool
	}{
		{
			name:             "chunked with no size",
			size:             -1,
			transferEncoding: "chunked",
			contentSha256:    "",
			expected:         true,
		},
		{
			name:             "streaming signature with no size",
			size:             -1,
			transferEncoding: "",
			contentSha256:    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			expected:         true,
		},
		{
			name:             "chunked with size specified",
			size:             1024,
			transferEncoding: "chunked",
			contentSha256:    "",
			expected:         false,
		},
		{
			name:             "normal request with size",
			size:             1024,
			transferEncoding: "",
			contentSha256:    "abcd1234",
			expected:         false,
		},
		{
			name:             "zero size not chunked",
			size:             0,
			transferEncoding: "",
			contentSha256:    "",
			expected:         false,
		},
		{
			name:             "empty everything",
			size:             -1,
			transferEncoding: "",
			contentSha256:    "",
			expected:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isChunkedWithoutSize(tt.size, tt.transferEncoding, tt.contentSha256)
			if result != tt.expected {
				t.Errorf("isChunkedWithoutSize(%d, %q, %q) = %v, want %v", 
					tt.size, tt.transferEncoding, tt.contentSha256, result, tt.expected)
			}
		})
	}
}

func TestGetCacheHeaders(t *testing.T) {
	tests := []struct {
		name           string
		key            string
		expectedCache  string
		expectedExists bool
	}{
		{
			name:           "Iceberg metadata file",
			key:            "warehouse/table1/metadata/metadata.json",
			expectedCache:  "private, max-age=5", // Actual implementation
			expectedExists: true,
		},
		{
			name:           "Iceberg manifest file",
			key:            "warehouse/table1/metadata/snap-123.avro",
			expectedCache:  "private, max-age=5", // Metadata cache for files in metadata directory
			expectedExists: true,
		},
		{
			name:           "Iceberg data file",
			key:            "warehouse/table1/data/file1.parquet",
			expectedCache:  "private, max-age=3600", // Data file cache
			expectedExists: true,
		},
		{
			name:           "regular file",
			key:            "warehouse/table1/readme.txt",
			expectedCache:  "",
			expectedExists: false,
		},
		{
			name:           "empty key",
			key:            "",
			expectedCache:  "",
			expectedExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, exists := getCacheHeaders(tt.key)
			if cache != tt.expectedCache {
				t.Errorf("getCacheHeaders(%q) cache = %q, want %q", tt.key, cache, tt.expectedCache)
			}
			if exists != tt.expectedExists {
				t.Errorf("getCacheHeaders(%q) exists = %v, want %v", tt.key, exists, tt.expectedExists)
			}
		})
	}
}

// Note: parseRange function is not implemented yet, so this test is commented out
// func TestParseRange(t *testing.T) { ... }