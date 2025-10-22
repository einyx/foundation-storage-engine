package s3

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/mux"
)

// Test different client types and their expected behaviors
func TestTrinoClientOperations(t *testing.T) {
	// Create handler with mock storage
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	trinoUserAgent := "aws-sdk-java/2.30.12 md/io#sync md/http#Apache ua/2.1 os/Linux lang/java#23.0.2 app/Trino"

	t.Run("TrinoIcebergMetadataRead", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/warehouse/customer_events/metadata/metadata.json", nil)
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

		// Verify Iceberg-specific optimizations
		if w.Header().Get("Cache-Control") != "private, max-age=5" {
			t.Errorf("Expected Iceberg metadata cache headers, got: %s", w.Header().Get("Cache-Control"))
		}
	})

	t.Run("TrinoDataUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/customer_events/data/file1.parquet", 
			bytes.NewReader([]byte("parquet data content")))
		req.Header.Set("User-Agent", trinoUserAgent)
		req.Header.Set("Content-Length", "20")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "customer_events/data/file1.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify Java SDK optimizations
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Trino client")
		}
		if w.Header().Get("Server") != "AmazonS3" {
			t.Error("Expected Server: AmazonS3 for Trino client")
		}
	})

	t.Run("TrinoChunkedUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/customer_events/data/chunked_file.parquet", 
			strings.NewReader("chunked content"))
		req.Header.Set("User-Agent", trinoUserAgent)
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "customer_events/data/chunked_file.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify streaming upload handling for Trino
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Trino chunked upload")
		}
	})
}

func TestHiveClientOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	hiveUserAgent := "aws-sdk-java/1.12.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hive/3.1.2"

	t.Run("HiveTableScan", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/warehouse/orders/data/year=2023/month=12/part-001.parquet", nil)
		req.Header.Set("User-Agent", hiveUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "orders/data/year=2023/month=12/part-001.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify Java SDK optimizations for Hive
		if w.Header().Get("Accept-Ranges") != "bytes" {
			t.Error("Expected Accept-Ranges: bytes for Hive data access")
		}
	})

	t.Run("HiveHeadOperation", func(t *testing.T) {
		req := httptest.NewRequest("HEAD", "/warehouse/orders/data/part-001.parquet", nil)
		req.Header.Set("User-Agent", hiveUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "orders/data/part-001.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify Java SDK HEAD optimizations
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Hive HEAD request")
		}
		if w.Header().Get("Server") != "AmazonS3" {
			t.Error("Expected Server: AmazonS3 for Hive client")
		}
	})
}

func TestHadoopS3AOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	hadoopUserAgent := "aws-sdk-java/1.11.1026 Linux/5.4.0 OpenJDK_64-Bit_Server_VM/11.0.16 java/11.0.16 vendor/Eclipse_Adoptium hadoop-s3a/3.3.4"

	t.Run("HadoopDataWrite", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/logs/data/log-2023-12-01.avro", 
			bytes.NewReader([]byte("avro log data")))
		req.Header.Set("User-Agent", hadoopUserAgent)
		req.Header.Set("Content-Length", "13")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "logs/data/log-2023-12-01.avro",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify Java SDK optimizations for Hadoop
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Hadoop S3A client")
		}
		if w.Header().Get("Content-Length") != "0" {
			t.Error("Expected Content-Length: 0 for Hadoop response")
		}
	})

	t.Run("HadoopMultipartUpload", func(t *testing.T) {
		// Initiate multipart upload
		req := httptest.NewRequest("POST", "/warehouse/logs/data/large-log.avro?uploads", nil)
		req.Header.Set("User-Agent", hadoopUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "logs/data/large-log.avro",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify response is XML
		if !strings.Contains(w.Header().Get("Content-Type"), "xml") {
			t.Error("Expected XML content type for multipart initiate response")
		}
	})
}

func TestSparkClientOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	sparkUserAgent := "aws-sdk-java/2.20.0 Spark/3.4.0 scala/2.12.17"

	t.Run("SparkDataWrite", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/analytics/data/spark-output-001.parquet", 
			bytes.NewReader([]byte("spark parquet output")))
		req.Header.Set("User-Agent", sparkUserAgent)
		req.Header.Set("Content-Length", "20")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "analytics/data/spark-output-001.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify Java SDK optimizations for Spark
		if w.Header().Get("Connection") != "close" {
			t.Error("Expected Connection: close for Spark client")
		}
	})

	t.Run("SparkDataRead", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/warehouse/analytics/data/input-001.parquet", nil)
		req.Header.Set("User-Agent", sparkUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "analytics/data/input-001.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify Iceberg data caching for Spark
		if w.Header().Get("Cache-Control") != "private, max-age=3600" {
			t.Errorf("Expected Iceberg data cache headers, got: %s", w.Header().Get("Cache-Control"))
		}
	})
}

func TestAWSCLIOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	awsCliUserAgent := "aws-cli/2.0.0 Python/3.8.0 Linux/5.4.0-74-generic source/x86_64.ubuntu.20"

	t.Run("AWSCLIUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/uploads/file.txt", 
			bytes.NewReader([]byte("uploaded content")))
		req.Header.Set("User-Agent", awsCliUserAgent)
		req.Header.Set("Content-Length", "16")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "uploads/file.txt",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// AWS CLI should NOT get Java SDK optimizations
		if w.Header().Get("Connection") == "close" {
			t.Error("Did not expect Connection: close for AWS CLI")
		}
	})

	t.Run("AWSCLIChunkedUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/uploads/chunked.txt", 
			strings.NewReader("chunked upload"))
		req.Header.Set("User-Agent", awsCliUserAgent)
		req.Header.Set("Content-Encoding", "aws-chunked")
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "uploads/chunked.txt",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// AWS CLI should get direct body reader for chunked uploads
		etag := w.Header().Get("ETag")
		if etag == "" {
			t.Error("Expected ETag in response")
		}
	})

	t.Run("AWSCLIListBuckets", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", awsCliUserAgent)
		req = createAdminContext(req)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should return XML bucket list
		if !strings.Contains(w.Header().Get("Content-Type"), "xml") {
			t.Error("Expected XML content type for bucket list")
		}
		if !strings.Contains(w.Body.String(), "ListAllMyBucketsResult") {
			t.Error("Expected ListAllMyBucketsResult in response body")
		}
	})
}

func TestMinIOClientOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	minioUserAgent := "MinIO (linux; amd64) minio-go/v7.0.0"
	mcUserAgent := "MinIO (linux; amd64) mc/2023-01-28T20-29-38Z"

	t.Run("MinIOClientUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/minio/test.json", 
			bytes.NewReader([]byte(`{"test": "data"}`)))
		req.Header.Set("User-Agent", minioUserAgent)
		req.Header.Set("Content-Length", "16")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "minio/test.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// MinIO should NOT get Java SDK optimizations
		if w.Header().Get("Connection") == "close" {
			t.Error("Did not expect Connection: close for MinIO client")
		}
	})

	t.Run("MCClientBucketList", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/warehouse", nil)
		req.Header.Set("User-Agent", mcUserAgent)
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Should handle MC client bucket validation
		if !strings.Contains(w.Header().Get("Content-Type"), "xml") {
			t.Error("Expected XML content type for object list")
		}
	})
}

func TestAzureSDKOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	azureUserAgent := "Azure-Storage/1.0.0 (language=Go; version=go1.19.0)"

	t.Run("AzureSDKUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/azure/blob.bin", 
			bytes.NewReader([]byte("azure blob data")))
		req.Header.Set("User-Agent", azureUserAgent)
		req.Header.Set("Content-Length", "15")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "azure/blob.bin",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Azure SDK should get specific response handling
		if w.Header().Get("x-amz-id-2") != "Azure/1760704234715636000" && 
		   !strings.Contains(w.Header().Get("x-amz-id-2"), "Azure/") {
			t.Error("Expected Azure-specific x-amz-id-2 header")
		}
	})
}

func TestBrowserClientOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	browserUserAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

	t.Run("BrowserOptionsRequest", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("User-Agent", browserUserAgent)
		req.Header.Set("Origin", "https://example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify CORS headers
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Expected CORS allow-origin header")
		}
		if w.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Error("Expected CORS allow-methods header")
		}
	})

	t.Run("BrowserUploadRequest", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/uploads/browser-file.txt", 
			bytes.NewReader([]byte("browser upload")))
		req.Header.Set("User-Agent", browserUserAgent)
		req.Header.Set("Content-Length", "14")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "uploads/browser-file.txt",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Browser should get standard response (no special optimizations)
		if w.Header().Get("Connection") == "close" {
			t.Error("Did not expect Connection: close for browser client")
		}
	})
}

func TestGenericClientOperations(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	genericUserAgent := "MyCustomApp/1.0.0"

	t.Run("GenericClientUpload", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/warehouse/generic/file.dat", 
			bytes.NewReader([]byte("generic data")))
		req.Header.Set("User-Agent", genericUserAgent)
		req.Header.Set("Content-Length", "12")
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "warehouse",
			"key":    "generic/file.dat",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Generic client should get standard response
		if w.Header().Get("ETag") == "" {
			t.Error("Expected ETag in response")
		}
		if w.Header().Get("x-amz-request-id") == "" {
			t.Error("Expected x-amz-request-id in response")
		}
	})
}

// Helper function to create authenticated admin context
func createAdminContext(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), "authenticated", true)
	ctx = context.WithValue(ctx, "is_admin", true)
	ctx = context.WithValue(ctx, "user_sub", "test-admin")
	ctx = context.WithValue(ctx, "bucket_access", map[string]bool{
		"warehouse":  true,
		"samples":    true,
		"connectors": true,
	})
	return req.WithContext(ctx)
}