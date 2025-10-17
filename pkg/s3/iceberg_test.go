package s3

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/mux"
)

func TestIcebergMetadataOptimizations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name                string
		key                 string
		expectedCacheControl string
		isIceberg           bool
	}{
		{
			name:                "main metadata file",
			key:                 "warehouse/customer_events/metadata/metadata.json",
			expectedCacheControl: "private, max-age=5", // Actual implementation
			isIceberg:           true,
		},
		{
			name:                "versioned metadata file",
			key:                 "warehouse/orders/metadata/v1.metadata.json",
			expectedCacheControl: "private, max-age=5", // Actual implementation
			isIceberg:           true,
		},
		{
			name:                "version hint file",
			key:                 "warehouse/sales/metadata/version-hint.text",
			expectedCacheControl: "private, max-age=5", // Metadata file gets metadata cache
			isIceberg:           true,
		},
		{
			name:                "snapshot file",
			key:                 "warehouse/events/metadata/snap-123456789.avro",
			expectedCacheControl: "private, max-age=5", // Metadata directory files get metadata cache
			isIceberg:           true,
		},
		{
			name:                "manifest list file",
			key:                 "warehouse/logs/metadata/snap-987654321-1-c87bfec7-d36c-4075-ad04-3dcb2ca0f2b5.avro",
			expectedCacheControl: "private, max-age=5", // Metadata directory files get metadata cache
			isIceberg:           true,
		},
		{
			name:                "manifest file",
			key:                 "warehouse/analytics/metadata/c87bfec7-d36c-4075-ad04-3dcb2ca0f2b5.avro",
			expectedCacheControl: "private, max-age=5", // Metadata directory files get metadata cache
			isIceberg:           true,
		},
		{
			name:        "regular json file",
			key:         "warehouse/config/settings.json",
			isIceberg:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/warehouse/"+tt.key, nil)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    tt.key,
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			if tt.isIceberg {
				cacheControl := w.Header().Get("Cache-Control")
				if cacheControl != tt.expectedCacheControl {
					t.Errorf("Expected Cache-Control %q, got %q", tt.expectedCacheControl, cacheControl)
				}
			} else {
				cacheControl := w.Header().Get("Cache-Control")
				if cacheControl != "" {
					t.Errorf("Expected no Cache-Control for non-Iceberg file, got %q", cacheControl)
				}
			}
		})
	}
}

func TestIcebergDataFileOptimizations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name                string
		key                 string
		expectedCacheControl string
		isIcebergData       bool
	}{
		{
			name:                "parquet data file",
			key:                 "warehouse/events/data/year=2023/month=12/day=01/file-001.parquet",
			expectedCacheControl: "private, max-age=3600", // Actual implementation
			isIcebergData:       true,
		},
		{
			name:                "orc data file",
			key:                 "warehouse/logs/data/partition-1/file-002.orc",
			expectedCacheControl: "private, max-age=3600", // Actual implementation
			isIcebergData:       true,
		},
		{
			name:                "avro data file",
			key:                 "warehouse/metrics/data/file-003.avro",
			expectedCacheControl: "private, max-age=3600", // Actual implementation
			isIcebergData:       true,
		},
		{
			name:          "metadata avro file",
			key:           "warehouse/events/metadata/manifest-001.avro",
			isIcebergData: false, // This is metadata, not data
		},
		{
			name:          "regular csv file",
			key:           "warehouse/imports/raw-data.csv",
			isIcebergData: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/warehouse/"+tt.key, nil)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    tt.key,
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			if tt.isIcebergData {
				cacheControl := w.Header().Get("Cache-Control")
				if cacheControl != tt.expectedCacheControl {
					t.Errorf("Expected Cache-Control %q for data file, got %q", tt.expectedCacheControl, cacheControl)
				}
			}
		})
	}
}

func TestIcebergTrinoOptimizations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	trinoUserAgent := "aws-sdk-java/2.30.12 md/io#sync md/http#Apache ua/2.1 os/Linux lang/java#23.0.2 app/Trino"

	t.Run("TrinoIcebergMetadataUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/iceberg_table/metadata/metadata.json", 
			strings.NewReader(`{"format-version": 2, "table-uuid": "test-uuid"}`))
		req.Header.Set("User-Agent", trinoUserAgent)
		req.Header.Set("Content-Length", "52")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "iceberg_table/metadata/metadata.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should get Java SDK optimizations
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Trino Iceberg metadata upload")
		}
		if w.Header().Get("Server") != "AmazonS3" {
			t.Error("Expected Server: AmazonS3 for Trino client")
		}
	})

	t.Run("TrinoIcebergDataRead", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/warehouse/iceberg_table/data/file-001.parquet", nil)
		req.Header.Set("User-Agent", trinoUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "iceberg_table/data/file-001.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should get Iceberg data caching
		if w.Header().Get("Cache-Control") != "private, max-age=3600" {
			t.Errorf("Expected Iceberg data cache headers, got: %s", w.Header().Get("Cache-Control"))
		}
	})

	t.Run("TrinoIcebergChunkedMetadataUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/iceberg_table/metadata/v2.metadata.json", 
			strings.NewReader(`{"format-version": 2, "table-uuid": "test-uuid", "schemas": []}`))
		req.Header.Set("User-Agent", trinoUserAgent)
		req.Header.Set("Transfer-Encoding", "chunked")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "iceberg_table/metadata/v2.metadata.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Iceberg metadata should always be buffered, even for Trino
		etag := w.Header().Get("ETag")
		if etag != `"chunked-upload-etag"` {
			t.Errorf("Expected chunked ETag for buffered Iceberg metadata, got %s", etag)
		}
	})

	t.Run("TrinoIcebergDataStreamingUpload", func(t *testing.T) {
		// Large data file that should NOT be buffered for Trino
		req := httptest.NewRequest("PUT", "/warehouse/iceberg_table/data/large-data.parquet", 
			strings.NewReader("large parquet data content"))
		req.Header.Set("User-Agent", trinoUserAgent)
		req.Header.Set("Transfer-Encoding", "chunked")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "iceberg_table/data/large-data.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Data files for Trino should use streaming (not buffered)
		etag := w.Header().Get("ETag")
		if etag != `"streaming-upload-etag"` {
			t.Errorf("Expected streaming ETag for Trino data upload, got %s", etag)
		}
	})
}

func TestIcebergTableNameExtraction(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "simple table name",
			key:      "warehouse/customer_events/metadata/metadata.json",
			expected: "customer_events",
		},
		{
			name:     "table with underscores",
			key:      "data_lake/user_behavior_analytics/data/file-001.parquet",
			expected: "user_behavior_analytics",
		},
		{
			name:     "nested namespace",
			key:      "prod/analytics/sales_metrics/metadata/v1.metadata.json",
			expected: "sales_metrics",
		},
		{
			name:     "partitioned data",
			key:      "warehouse/events/data/year=2023/month=12/file.parquet",
			expected: "events",
		},
		{
			name:     "manifest file",
			key:      "warehouse/logs/metadata/snap-123-1-uuid.avro",
			expected: "logs",
		},
		{
			name:     "complex table name",
			key:      "data/customer_order_line_items/metadata/metadata.json",
			expected: "customer_order_line_items",
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

func TestIcebergFileTypeDetection(t *testing.T) {
	tests := []struct {
		name           string
		key            string
		isMetadata     bool
		isManifest     bool
		isData         bool
		isAvro         bool
	}{
		{
			name:       "metadata json",
			key:        "warehouse/table1/metadata/metadata.json",
			isMetadata: true,
		},
		{
			name:       "versioned metadata",
			key:        "warehouse/table1/metadata/v5.metadata.json",
			isMetadata: true,
		},
		{
			name:       "version hint",
			key:        "warehouse/table1/metadata/version-hint.text",
			isMetadata: true,
		},
		{
			name:       "snapshot manifest list",
			key:        "warehouse/table1/metadata/snap-123-1-uuid.avro",
			isMetadata: true,
			isManifest: true,
			isAvro:     true,
		},
		{
			name:       "manifest file",
			key:        "warehouse/table1/metadata/uuid-manifest.avro",
			isMetadata: true,
			isManifest: true,
			isAvro:     true,
		},
		{
			name:   "parquet data file",
			key:    "warehouse/table1/data/file-001.parquet",
			isData: true,
		},
		{
			name:   "orc data file",
			key:    "warehouse/table1/data/partition/file.orc",
			isData: true,
		},
		{
			name:   "avro data file",
			key:    "warehouse/table1/data/avro-file.avro",
			isData: true,
			isAvro: true,
		},
		{
			name: "regular file",
			key:  "warehouse/table1/readme.txt",
		},
		{
			name: "config file",
			key:  "warehouse/config.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isIcebergMetadata(tt.key) != tt.isMetadata {
				t.Errorf("isIcebergMetadata(%q) = %v, want %v", tt.key, isIcebergMetadata(tt.key), tt.isMetadata)
			}
			if isIcebergManifest(tt.key) != tt.isManifest {
				t.Errorf("isIcebergManifest(%q) = %v, want %v", tt.key, isIcebergManifest(tt.key), tt.isManifest)
			}
			if isIcebergData(tt.key) != tt.isData {
				t.Errorf("isIcebergData(%q) = %v, want %v", tt.key, isIcebergData(tt.key), tt.isData)
			}
			if isAvroFile(tt.key) != tt.isAvro {
				t.Errorf("isAvroFile(%q) = %v, want %v", tt.key, isAvroFile(tt.key), tt.isAvro)
			}
		})
	}
}

func TestIcebergMultipartUploadOptimizations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	trinoUserAgent := "aws-sdk-java/2.30.12 app/Trino"

	t.Run("IcebergMetadataMultipartInitiate", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/warehouse/events/metadata/large-metadata.json?uploads", nil)
		req.Header.Set("User-Agent", trinoUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "events/metadata/large-metadata.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should contain upload ID in XML response
		if !strings.Contains(w.Body.String(), "UploadId") {
			t.Error("Expected UploadId in multipart initiate response")
		}
	})

	t.Run("IcebergDataMultipartPart", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/events/data/large-file.parquet?uploadId=test-upload&partNumber=1", 
			bytes.NewReader([]byte("parquet data chunk")))
		req.Header.Set("User-Agent", trinoUserAgent)
		req.Header.Set("Content-Length", "18")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "events/data/large-file.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should return part ETag
		etag := w.Header().Get("ETag")
		if !strings.Contains(etag, "part-1-etag") {
			t.Errorf("Expected part ETag, got %s", etag)
		}
	})
}

func TestIcebergHEADRequestOptimizations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	trinoUserAgent := "aws-sdk-java/2.30.12 app/Trino"

	t.Run("TrinoIcebergMetadataHEAD", func(t *testing.T) {
		req := httptest.NewRequest("HEAD", "/warehouse/customer_events/metadata/metadata.json", nil)
		req.Header.Set("User-Agent", trinoUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "customer_events/metadata/metadata.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should get both Trino and Iceberg optimizations
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Trino Iceberg HEAD request")
		}
		if w.Header().Get("Server") != "AmazonS3" {
			t.Error("Expected Server: AmazonS3 for Trino client")
		}
	})

	t.Run("RegularClientIcebergHEAD", func(t *testing.T) {
		req := httptest.NewRequest("HEAD", "/warehouse/customer_events/metadata/metadata.json", nil)
		req.Header.Set("User-Agent", "regular-client/1.0")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "customer_events/metadata/metadata.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Regular clients should get Connection: close for Iceberg metadata files for optimization
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Iceberg metadata file")
		}
	})
}

func TestIcebergVersionedMetadataHandling(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	versionedFiles := []string{
		"warehouse/table1/metadata/v1.metadata.json",
		"warehouse/table1/metadata/v10.metadata.json",
		"warehouse/table1/metadata/v999.metadata.json",
		"warehouse/table1/metadata/metadata.json", // Current version
	}

	for _, file := range versionedFiles {
		t.Run(file, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/"+file, nil)
			req = createAdminContext(req)
			
			parts := strings.Split(file, "/")
			bucket := parts[0]
			key := strings.Join(parts[1:], "/")
			
			req = mux.SetURLVars(req, map[string]string{
				"bucket": bucket,
				"key":    key,
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s, got %d", file, w.Code)
			}

			// All versioned metadata should get appropriate caching
			if w.Header().Get("Cache-Control") != "private, max-age=5" {
				t.Errorf("Expected metadata cache headers for %s, got: %s", 
					file, w.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestIcebergNamespaceHandling(t *testing.T) {
	// Test various namespace patterns that Iceberg uses
	namespacePatterns := []struct {
		key           string
		expectedTable string
	}{
		{
			key:           "warehouse.db/table1/metadata/metadata.json",
			expectedTable: "table1", // Part before metadata directory
		},
		{
			key:           "production/analytics/customer_metrics/data/file.parquet",
			expectedTable: "customer_metrics", // Part before data directory
		},
		{
			key:           "dev.schema.table/metadata/snap-123.avro",
			expectedTable: "dev.schema.table", // Part before metadata directory
		},
		{
			key:           "namespace1/namespace2/namespace3/table_name/metadata/metadata.json",
			expectedTable: "table_name", // Part before metadata directory
		},
	}

	for _, pattern := range namespacePatterns {
		t.Run(pattern.key, func(t *testing.T) {
			tableName := extractTableName(pattern.key)
			if tableName != pattern.expectedTable {
				t.Errorf("extractTableName(%q) = %q, want %q", 
					pattern.key, tableName, pattern.expectedTable)
			}
		})
	}
}

func TestIcebergCacheHeadersConsistency(t *testing.T) {
	// Test that cache headers are consistent across different request types
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	metadataFile := "warehouse/events/metadata/metadata.json"
	dataFile := "warehouse/events/data/file-001.parquet"

	// Test GET requests
	for _, file := range []string{metadataFile, dataFile} {
		t.Run("GET_"+file, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/"+file, nil)
			req = createAdminContext(req)
			
			parts := strings.Split(file, "/")
			req = mux.SetURLVars(req, map[string]string{
				"bucket": parts[0],
				"key":    strings.Join(parts[1:], "/"),
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			cacheControl := w.Header().Get("Cache-Control")
			if cacheControl == "" {
				t.Errorf("Expected Cache-Control header for Iceberg file %s", file)
			}
		})
	}

	// Test HEAD requests should have same cache headers
	for _, file := range []string{metadataFile, dataFile} {
		t.Run("HEAD_"+file, func(t *testing.T) {
			req := httptest.NewRequest("HEAD", "/"+file, nil)
			req = createAdminContext(req)
			
			parts := strings.Split(file, "/")
			req = mux.SetURLVars(req, map[string]string{
				"bucket": parts[0],
				"key":    strings.Join(parts[1:], "/"),
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			cacheControl := w.Header().Get("Cache-Control")
			if cacheControl == "" {
				t.Errorf("Expected Cache-Control header for HEAD request of Iceberg file %s", file)
			}
		})
	}
}