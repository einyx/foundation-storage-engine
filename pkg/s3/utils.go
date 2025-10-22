package s3

import (
	"strings"
)

// extractTableName tries to extract the table name from an Iceberg path
func extractTableName(key string) string {
	parts := strings.Split(key, "/")
	
	// Look for table name before metadata or data directories
	for i, part := range parts {
		if (part == "metadata" || part == "data") && i > 0 {
			return parts[i-1]
		}
	}
	
	// Check for underscore prefix pattern
	for i, part := range parts {
		if strings.HasPrefix(part, "_") && i > 0 {
			return parts[i-1]
		}
	}
	
	// Fallback to second-to-last part
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return "unknown"
}

// isIcebergMetadata checks if the key represents an Iceberg metadata file
func isIcebergMetadata(key string) bool {
	// Must be in metadata directory
	if !strings.Contains(key, "/metadata/") {
		return false
	}
	
	// Check for various Iceberg metadata file types
	return strings.HasSuffix(key, ".json") ||
		strings.HasSuffix(key, ".text") ||
		strings.HasSuffix(key, ".avro") ||
		strings.Contains(key, "metadata.json") ||
		strings.Contains(key, "version-hint") ||
		strings.Contains(key, "snap-") ||
		strings.Contains(key, "manifest")
}

// isIcebergManifest checks if the key represents an Iceberg manifest file
func isIcebergManifest(key string) bool {
	return strings.Contains(key, "manifest") || strings.Contains(key, "snap-")
}

// isIcebergData checks if the key represents Iceberg data files
func isIcebergData(key string) bool {
	return strings.Contains(key, "/data/")
}

// isAvroFile checks if the key represents an Avro file
func isAvroFile(key string) bool {
	return strings.HasSuffix(key, ".avro")
}

// isChunkedWithoutSize detects chunked transfers without explicit Content-Length
func isChunkedWithoutSize(size int64, transferEncoding, contentSha256 string) bool {
	return size < 0 && (transferEncoding == "chunked" ||
		contentSha256 == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
}

// getCacheHeaders returns appropriate cache headers based on file type
func getCacheHeaders(key string) (string, bool) {
	if isIcebergMetadata(key) {
		// Iceberg metadata files change frequently, so use short cache
		return "private, max-age=5", true
	} else if isIcebergData(key) || isAvroFile(key) {
		// Data files are immutable once written
		return "private, max-age=3600", true
	}
	return "", false
}

// isJavaSDKClient detects Java SDK clients (Trino, Hive, Hadoop, etc.)
func isJavaSDKClient(userAgent string) bool {
	userAgentLower := strings.ToLower(userAgent)
	return strings.Contains(userAgentLower, "trino") ||
		strings.Contains(userAgentLower, "presto") ||
		(strings.Contains(userAgentLower, "java") && strings.Contains(userAgent, "app/Trino")) ||
		strings.Contains(userAgentLower, "hive") ||
		strings.Contains(userAgentLower, "hadoop") ||
		strings.Contains(userAgentLower, "s3a") ||
		strings.Contains(userAgentLower, "spark")
}

// isAWSCLIClient detects AWS CLI clients
func isAWSCLIClient(userAgent string) bool {
	return strings.Contains(strings.ToLower(userAgent), "aws-cli")
}
