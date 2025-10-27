package s3

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/mux"
)

func TestTrinoAdvancedOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Real Trino user agents from production environments
	trinoUserAgents := []string{
		"aws-sdk-java/2.30.12 md/io#sync md/http#Apache ua/2.1 os/Linux lang/java#23.0.2 app/Trino",
		"aws-sdk-java/2.25.11 Linux/5.15.0-75-generic OpenJDK_64-Bit_Server_VM/17.0.7 java/17.0.7 vendor/Eclipse_Adoptium app/Trino",
		"aws-sdk-java/2.21.0 md/io#sync ua/2.1 os/Linux#5.4.0-150-generic lang/java#11.0.19 app/Trino/414",
		"Trino/412 aws-sdk-java/2.20.12",
	}

	for i, userAgent := range trinoUserAgents {
		t.Run(fmt.Sprintf("TrinoVariant_%d", i+1), func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/warehouse/iceberg_table/data/chunk-001.parquet",
				bytes.NewReader([]byte("iceberg parquet data chunk")))
			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("Content-Length", "26")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "iceberg_table/data/chunk-001.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for Trino variant %d, got %d", i+1, w.Code)
			}

			// All Trino variants should get Java SDK optimizations
			if w.Header().Get("Connection") != "close" {
				t.Errorf("Expected Connection: close for Trino variant %d", i+1)
			}
			if w.Header().Get("Server") != "AmazonS3" {
				t.Errorf("Expected Server: AmazonS3 for Trino variant %d", i+1)
			}
		})
	}
}

func TestJavaSDKBotoEquivalents(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Java SDK equivalents to Python boto3 operations
	tests := []struct {
		name      string
		userAgent string
		operation string
		expected  bool // whether it should get Java SDK optimizations
	}{
		{
			name:      "Java SDK with Hive",
			userAgent: "aws-sdk-java/1.12.613 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/11.0.19 java/11.0.19 vendor/Eclipse_Adoptium hive/3.1.3",
			operation: "PUT",
			expected:  true,
		},
		{
			name:      "Java SDK with Hadoop S3A",
			userAgent: "aws-sdk-java/1.11.1026 Linux/5.4.0-150-generic OpenJDK_64-Bit_Server_VM/11.0.19 java/11.0.19 vendor/Eclipse_Adoptium hadoop-s3a/3.3.4",
			operation: "PUT",
			expected:  true,
		},
		{
			name:      "Java SDK with Spark",
			userAgent: "aws-sdk-java/2.20.160 Spark/3.4.1 scala/2.12.17",
			operation: "PUT",
			expected:  true,
		},
		{
			name:      "Generic Java SDK (no optimization)",
			userAgent: "aws-sdk-java/2.20.160 java/11.0.19",
			operation: "PUT",
			expected:  false,
		},
		{
			name:      "Python boto3 (no optimization)",
			userAgent: "Boto3/1.34.0 Python/3.9.16 Linux/5.15.0-75-generic source/x86_64.ubuntu.20.04 Botocore/1.34.0",
			operation: "PUT",
			expected:  false,
		},
		{
			name:      "Python boto3 with aiobotocore",
			userAgent: "aiobotocore/2.5.2 Python/3.11.4 aiohttp/3.8.5",
			operation: "PUT",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.operation, "/warehouse/test/data.txt",
				bytes.NewReader([]byte("test data")))
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Content-Length", "9")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "test/data.txt",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s, got %d", tt.name, w.Code)
			}

			if tt.expected {
				if w.Header().Get("Connection") != "close" {
					t.Errorf("Expected Connection: close for %s", tt.name)
				}
				if w.Header().Get("Server") != "AmazonS3" {
					t.Errorf("Expected Server: AmazonS3 for %s", tt.name)
				}
			} else {
				if w.Header().Get("Connection") == "close" {
					t.Errorf("Did not expect Connection: close for %s", tt.name)
				}
			}
		})
	}
}

func TestPySparkWithJavaSDK(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// PySpark often uses Java SDK under the hood
	pySparkUserAgents := []string{
		"aws-sdk-java/2.20.12 Spark/3.4.0 scala/2.12.17 pyspark/3.4.0",
		"aws-sdk-java/2.17.290 Spark/3.3.2 scala/2.12.15",
		"aws-sdk-java/1.12.500 hadoop-aws/3.3.4 spark/3.4.1",
	}

	for i, userAgent := range pySparkUserAgents {
		t.Run(fmt.Sprintf("PySpark_%d", i+1), func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/warehouse/delta_table/data/part-001.parquet",
				bytes.NewReader([]byte("delta parquet data")))
			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("Content-Length", "18")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "delta_table/data/part-001.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for PySpark variant %d, got %d", i+1, w.Code)
			}

			// PySpark with Java SDK should get optimizations
			if w.Header().Get("Connection") != "close" {
				t.Errorf("Expected Connection: close for PySpark variant %d", i+1)
			}
		})
	}
}

func TestDatabricksClientOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Databricks environments often use specific user agents
	databricksUserAgents := []string{
		"aws-sdk-java/2.20.12 Databricks/12.2.x-scala2.12 Spark/3.4.0",
		"aws-sdk-java/1.12.470 databricks-runtime/11.3.x-scala2.12",
		"Databricks-Connect/12.2.0 aws-sdk-java/2.20.0",
	}

	for i, userAgent := range databricksUserAgents {
		t.Run(fmt.Sprintf("Databricks_%d", i+1), func(t *testing.T) {
			req := httptest.NewRequest("GET", "/warehouse/delta_lake/data/checkpoint.parquet", nil)
			req.Header.Set("User-Agent", userAgent)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "delta_lake/data/checkpoint.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for Databricks variant %d, got %d", i+1, w.Code)
			}

			// Check for Iceberg data caching (since it's a parquet file in data directory)
			if w.Header().Get("Cache-Control") != "private, max-age=3600" {
				t.Errorf("Expected Iceberg data cache headers for Databricks variant %d, got: %s",
					i+1, w.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestSnowflakeConnectorOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Snowflake connectors and COPY operations
	snowflakeUserAgents := []string{
		"snowflake-connector-java/3.13.30",
		"SnowflakeDB/1.0 (Snowflake Data Cloud)",
		"aws-sdk-java/1.12.400 snowflake-jdbc/3.13.30",
	}

	for i, userAgent := range snowflakeUserAgents {
		t.Run(fmt.Sprintf("Snowflake_%d", i+1), func(t *testing.T) {
			req := httptest.NewRequest("GET", "/warehouse/external_tables/data.csv", nil)
			req.Header.Set("User-Agent", userAgent)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "external_tables/data.csv",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for Snowflake variant %d, got %d", i+1, w.Code)
			}

			// Snowflake should get standard response (no special optimizations)
			if w.Header().Get("Accept-Ranges") != "bytes" {
				t.Errorf("Expected Accept-Ranges: bytes for Snowflake variant %d", i+1)
			}
		})
	}
}

func TestFlinkkConnectorOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Apache Flink S3 connectors
	flinkUserAgents := []string{
		"aws-sdk-java/2.20.12 flink/1.17.0",
		"flink-s3-fs-hadoop/1.17.0 aws-sdk-java/1.12.400",
		"aws-sdk-java/2.17.290 Apache-Flink/1.16.2",
	}

	for i, userAgent := range flinkUserAgents {
		t.Run(fmt.Sprintf("Flink_%d", i+1), func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/warehouse/streaming/checkpoint/state.bin",
				bytes.NewReader([]byte("flink checkpoint data")))
			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("Content-Length", "21")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "streaming/checkpoint/state.bin",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for Flink variant %d, got %d", i+1, w.Code)
			}

			// Flink should get standard response
			etag := w.Header().Get("ETag")
			if etag == "" {
				t.Errorf("Expected ETag for Flink variant %d", i+1)
			}
		})
	}
}

func TestPrestoTrinoCompatibility(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Presto (now Trino) compatibility tests
	prestoTrinoUserAgents := []string{
		"presto-cli/0.280 aws-sdk-java/1.12.300",
		"prestodb/0.280 aws-sdk-java/1.12.300",
		"trino-cli/414 aws-sdk-java/2.20.12",
		"aws-sdk-java/2.20.12 trino/414",
	}

	for i, userAgent := range prestoTrinoUserAgents {
		t.Run(fmt.Sprintf("PrestoTrino_%d", i+1), func(t *testing.T) {
			req := httptest.NewRequest("HEAD", "/warehouse/hive_tables/orders/data.parquet", nil)
			req.Header.Set("User-Agent", userAgent)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "hive_tables/orders/data.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for Presto/Trino variant %d, got %d", i+1, w.Code)
			}

			// Should get Java SDK optimizations for Trino-like clients
			if strings.Contains(strings.ToLower(userAgent), "trino") ||
				strings.Contains(strings.ToLower(userAgent), "presto") {
				if w.Header().Get("Connection") != "close" {
					t.Errorf("Expected Connection: close for Presto/Trino variant %d", i+1)
				}
			}
		})
	}
}

func TestDataBricksUnityTrinoIntegration(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Databricks Unity Catalog with Trino integration
	req := httptest.NewRequest("GET", "/warehouse/unity_catalog/schema1/iceberg_table/metadata/metadata.json", nil)
	req.Header.Set("User-Agent", "aws-sdk-java/2.20.12 Databricks-Unity/1.0 app/Trino")
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "warehouse",
		"key":    "unity_catalog/schema1/iceberg_table/metadata/metadata.json",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Should get both Trino optimizations and Iceberg caching
	if w.Header().Get("Connection") != "close" {
		t.Error("Expected Connection: close for Databricks Unity + Trino")
	}
	if w.Header().Get("Cache-Control") != "private, max-age=5" {
		t.Errorf("Expected Iceberg metadata cache headers, got: %s", w.Header().Get("Cache-Control"))
	}
}

func TestClientSpecificErrorHandling(t *testing.T) {
	storage := newErrorMockStorage()
	storage.SimulateError("GetObject", errors.New("table not found"))

	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Test error handling for different client types
	clientTests := []struct {
		name      string
		userAgent string
		path      string
	}{
		{
			name:      "Trino error handling",
			userAgent: "aws-sdk-java/2.30.12 app/Trino",
			path:      "/warehouse/missing_table/metadata/metadata.json",
		},
		{
			name:      "Spark error handling",
			userAgent: "aws-sdk-java/2.20.12 Spark/3.4.0",
			path:      "/warehouse/missing_table/data/file.parquet",
		},
		{
			name:      "Hive error handling",
			userAgent: "aws-sdk-java/1.12.0 hive/3.1.2",
			path:      "/warehouse/missing_table/data/file.orc",
		},
	}

	for _, tt := range clientTests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req = createAdminContext(req)

			parts := strings.Split(strings.TrimPrefix(tt.path, "/"), "/")
			req = mux.SetURLVars(req, map[string]string{
				"bucket": parts[0],
				"key":    strings.Join(parts[1:], "/"),
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusNotFound {
				t.Errorf("Expected status 404 for %s, got %d", tt.name, w.Code)
			}

			// Error responses should be XML
			if !strings.Contains(w.Header().Get("Content-Type"), "xml") {
				t.Errorf("Expected XML error response for %s", tt.name)
			}
		})
	}
}

func TestMultipartUploadWithDifferentClients(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	clients := []struct {
		name      string
		userAgent string
	}{
		{
			name:      "Trino multipart",
			userAgent: "aws-sdk-java/2.30.12 app/Trino",
		},
		{
			name:      "Spark multipart",
			userAgent: "aws-sdk-java/2.20.12 Spark/3.4.0",
		},
		{
			name:      "Hadoop S3A multipart",
			userAgent: "aws-sdk-java/1.11.1026 hadoop-s3a/3.3.4",
		},
		{
			name:      "AWS CLI multipart",
			userAgent: "aws-cli/2.0.0",
		},
	}

	const testUploadID = "test-upload-id-123456"

	for _, client := range clients {
		t.Run(client.name+"_initiate", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/warehouse/large_files/bigdata.parquet?uploads", nil)
			req.Header.Set("User-Agent", client.userAgent)
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "large_files/bigdata.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s initiate, got %d", client.name, w.Code)
			}

			if !strings.Contains(w.Body.String(), "UploadId") {
				t.Errorf("Expected UploadId in response for %s", client.name)
			}
		})

		t.Run(client.name+"_part", func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/warehouse/large_files/bigdata.parquet?uploadId="+testUploadID+"&partNumber=1",
				bytes.NewReader([]byte("part data chunk")))
			req.Header.Set("User-Agent", client.userAgent)
			req.Header.Set("Content-Length", "15")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "large_files/bigdata.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s part upload, got %d", client.name, w.Code)
			}

			etag := w.Header().Get("ETag")
			if !strings.Contains(etag, "d41d8cd98f00b204e9800998ecf8427e-1") {
				t.Errorf("Expected part ETag for %s, got %s", client.name, etag)
			}
		})

		t.Run(client.name+"_complete", func(t *testing.T) {
			completeBody := `<CompleteMultipartUpload>
                <Part>
                    <PartNumber>1</PartNumber>
                    <ETag>"d41d8cd98f00b204e9800998ecf8427e-1"</ETag>
                </Part>
            </CompleteMultipartUpload>`

			req := httptest.NewRequest("POST", "/warehouse/large_files/bigdata.parquet?uploadId="+testUploadID,
				strings.NewReader(completeBody))
			req.Header.Set("User-Agent", client.userAgent)
			req.Header.Set("Content-Type", "application/xml")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "warehouse",
				"key":    "large_files/bigdata.parquet",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s complete, got %d", client.name, w.Code)
			}

			if !strings.Contains(w.Body.String(), "CompleteMultipartUploadResult") {
				t.Errorf("Expected completion result for %s", client.name)
			}
		})
	}
}
