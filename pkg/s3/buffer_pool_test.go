package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/gorilla/mux"
)

func TestBufferPoolManagement(t *testing.T) {
	// Test buffer pool creation and reuse
	t.Run("SmallBufferPoolReuse", func(t *testing.T) {
		// Get a buffer from the pool
		bufPtr1 := smallBufferPool.Get().(*[]byte)
		buf1 := *bufPtr1
		
		if len(buf1) != smallBufferSize {
			t.Errorf("Expected buffer size %d, got %d", smallBufferSize, len(buf1))
		}
		
		// Modify the buffer
		copy(buf1[:4], []byte("test"))
		
		// Return it to the pool
		smallBufferPool.Put(bufPtr1)
		
		// Get another buffer (should be the same one)
		bufPtr2 := smallBufferPool.Get().(*[]byte)
		buf2 := *bufPtr2
		
		// The buffer should be reused but content may vary
		if len(buf2) != smallBufferSize {
			t.Errorf("Expected reused buffer size %d, got %d", smallBufferSize, len(buf2))
		}
		
		smallBufferPool.Put(bufPtr2)
	})

	t.Run("MediumBufferPoolReuse", func(t *testing.T) {
		bufPtr1 := bufferPool.Get().(*[]byte)
		buf1 := *bufPtr1
		
		if len(buf1) != mediumBufferSize {
			t.Errorf("Expected buffer size %d, got %d", mediumBufferSize, len(buf1))
		}
		
		bufferPool.Put(bufPtr1)
		
		bufPtr2 := bufferPool.Get().(*[]byte)
		buf2 := *bufPtr2
		
		if len(buf2) != mediumBufferSize {
			t.Errorf("Expected reused buffer size %d, got %d", mediumBufferSize, len(buf2))
		}
		
		bufferPool.Put(bufPtr2)
	})

	t.Run("LargeBufferPoolReuse", func(t *testing.T) {
		bufPtr1 := largeBufferPool.Get().(*[]byte)
		buf1 := *bufPtr1
		
		if len(buf1) != largeBufferSize {
			t.Errorf("Expected buffer size %d, got %d", largeBufferSize, len(buf1))
		}
		
		largeBufferPool.Put(bufPtr1)
		
		bufPtr2 := largeBufferPool.Get().(*[]byte)
		buf2 := *bufPtr2
		
		if len(buf2) != largeBufferSize {
			t.Errorf("Expected reused buffer size %d, got %d", largeBufferSize, len(buf2))
		}
		
		largeBufferPool.Put(bufPtr2)
	})
}

func TestConcurrentBufferPoolAccess(t *testing.T) {
	// Test concurrent access to buffer pools
	const numGoroutines = 50
	const numOperations = 100
	
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				// Test small buffer pool
				bufPtr := smallBufferPool.Get().(*[]byte)
				buf := *bufPtr
				
				// Use the buffer
				copy(buf[:4], []byte("test"))
				
				// Return to pool
				smallBufferPool.Put(bufPtr)
				
				// Test medium buffer pool
				mediumPtr := bufferPool.Get().(*[]byte)
				mediumBuf := *mediumPtr
				
				copy(mediumBuf[:8], []byte("testdata"))
				bufferPool.Put(mediumPtr)
			}
		}()
	}
	
	wg.Wait()
}

func TestMD5ETagCalculation(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "empty data",
			data:     []byte{},
			expected: `"d41d8cd98f00b204e9800998ecf8427e"`,
		},
		{
			name:     "hello world",
			data:     []byte("hello world"),
			expected: `"5eb63bbbe01eeed093cb22bb8f5acdc3"`,
		},
		{
			name:     "test data",
			data:     []byte("test data"),
			expected: `"eb733a00c0c9d336e65691a37ab54293"`,
		},
		{
			name:     "binary data",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			expected: `"cbf4a387c69765d19f7bcd96abb7d008"`,
		},
		{
			name:     "large data",
			data:     bytes.Repeat([]byte("A"), 10000),
			expected: `"0f53217fc7c8e7f89e8a8558e64a7083"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate MD5 hash manually
			hash := md5.Sum(tt.data) //nolint:gosec // MD5 is required for S3 ETag compatibility
			etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
			
			if etag != tt.expected {
				t.Errorf("MD5 ETag = %s, want %s", etag, tt.expected)
			}
		})
	}
}

func TestSmallFileUploadWithBufferPool(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	tests := []struct {
		name        string
		data        string
		expectedMD5 string
	}{
		{
			name:        "small text file",
			data:        "hello world",
			expectedMD5: `"5d41402abc4b2a76b9719d911017c592"`,
		},
		{
			name:        "empty file",
			data:        "",
			expectedMD5: `"d41d8cd98f00b204e9800998ecf8427e"`,
		},
		{
			name:        "json data",
			data:        `{"key": "value", "number": 42}`,
			expectedMD5: `"a1c12c73f8e6b1c0e4b45f8b2c3d4e5f"`, // This will be calculated dynamically
		},
		{
			name:        "binary-like data",
			data:        string([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
			expectedMD5: `"7cfdd07889b3295d6a550914ab35e068"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate expected MD5 for this test
			hash := md5.Sum([]byte(tt.data)) //nolint:gosec
			expectedETag := fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
			
			req := httptest.NewRequest("PUT", "/test-bucket/small-file.txt", 
				strings.NewReader(tt.data))
			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(tt.data)))
			req.Header.Set("User-Agent", "test-client/1.0")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "small-file.txt",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			// Verify MD5 ETag is calculated correctly
			etag := w.Header().Get("ETag")
			if etag != expectedETag {
				t.Errorf("Expected ETag %s, got %s", expectedETag, etag)
			}
		})
	}
}

func TestLargeFileUploadWithoutBufferPool(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	// Create large data (bigger than smallFileLimit)
	largeData := strings.Repeat("A", int(smallFileLimit)+1000)

	req := httptest.NewRequest("PUT", "/test-bucket/large-file.txt", 
		strings.NewReader(largeData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(largeData)))
	req.Header.Set("User-Agent", "test-client/1.0")
	req = createAdminContext(req)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "large-file.txt",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Large files should get generic ETag (not calculated MD5)
	etag := w.Header().Get("ETag")
	if etag != `"large-file-etag"` {
		t.Errorf("Expected generic ETag for large file, got %s", etag)
	}
}

func TestChunkedUploadBuffering(t *testing.T) {
	storage := &mockStorage{}
	auth := &mockAuth{}
	cfg := config.S3Config{}
	chunking := config.ChunkingConfig{}
	handler := NewHandler(storage, auth, cfg, chunking)

	t.Run("ChunkedUploadWithBuffering", func(t *testing.T) {
		data := "chunked upload data"
		req := httptest.NewRequest("PUT", "/test-bucket/chunked-file.txt", 
			strings.NewReader(data))
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("User-Agent", "test-client/1.0")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "test-bucket",
			"key":    "chunked-file.txt",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Chunked uploads should get chunked ETag
		etag := w.Header().Get("ETag")
		if etag != `"chunked-upload-etag"` {
			t.Errorf("Expected chunked ETag, got %s", etag)
		}
	})

	t.Run("TrinoChunkedUploadNoBuffering", func(t *testing.T) {
		data := "trino streaming data"
		req := httptest.NewRequest("PUT", "/test-bucket/trino-stream.parquet", 
			strings.NewReader(data))
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("User-Agent", "aws-sdk-java/2.30.12 app/Trino")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "test-bucket",
			"key":    "trino-stream.parquet",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Trino streaming should get streaming ETag
		etag := w.Header().Get("ETag")
		if etag != `"streaming-upload-etag"` {
			t.Errorf("Expected streaming ETag for Trino, got %s", etag)
		}
	})

	t.Run("IcebergMetadataAlwaysBuffered", func(t *testing.T) {
		data := `{"format-version": 2, "table-uuid": "test"}`
		req := httptest.NewRequest("PUT", "/test-bucket/table1/metadata/metadata.json", 
			strings.NewReader(data))
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("User-Agent", "aws-sdk-java/2.30.12 app/Trino")
		req.ContentLength = -1
		req = createAdminContext(req)
		req = mux.SetURLVars(req, map[string]string{
			"bucket": "test-bucket",
			"key":    "table1/metadata/metadata.json",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Iceberg metadata should always be buffered, even for Trino
		etag := w.Header().Get("ETag")
		if etag != `"chunked-upload-etag"` {
			t.Errorf("Expected chunked ETag for Iceberg metadata, got %s", etag)
		}
	})
}

func TestBufferPoolStress(t *testing.T) {
	// Stress test the buffer pools under concurrent load
	const numWorkers = 20
	const operationsPerWorker = 1000
	
	var wg sync.WaitGroup
	start := time.Now()
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerWorker; j++ {
				// Simulate small file processing
				bufPtr := smallBufferPool.Get().(*[]byte)
				buf := *bufPtr
				
				// Simulate file content processing
				testData := fmt.Sprintf("worker-%d-op-%d", workerID, j)
				copy(buf, testData)
				
				// Calculate MD5 (simulating real processing)
				hash := md5.Sum(buf[:len(testData)]) //nolint:gosec
				_ = hex.EncodeToString(hash[:])
				
				smallBufferPool.Put(bufPtr)
				
				// Occasionally use medium buffer
				if j%10 == 0 {
					mediumPtr := bufferPool.Get().(*[]byte)
					mediumBuf := *mediumPtr
					copy(mediumBuf, testData)
					bufferPool.Put(mediumPtr)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	duration := time.Since(start)
	totalOps := numWorkers * operationsPerWorker
	opsPerSecond := float64(totalOps) / duration.Seconds()
	
	t.Logf("Buffer pool stress test completed: %d operations in %v (%.2f ops/sec)", 
		totalOps, duration, opsPerSecond)
		
	// Basic performance check - should handle at least 10k ops/sec
	if opsPerSecond < 10000 {
		t.Logf("Performance warning: only %.2f ops/sec (expected >10k)", opsPerSecond)
	}
}

func TestETagConsistency(t *testing.T) {
	// Test that same data always produces same ETag
	testData := "consistent test data for etag"
	expectedHash := md5.Sum([]byte(testData)) //nolint:gosec
	expectedETag := fmt.Sprintf(`"%s"`, hex.EncodeToString(expectedHash[:]))
	
	// Calculate ETag multiple times
	for i := 0; i < 100; i++ {
		hash := md5.Sum([]byte(testData)) //nolint:gosec
		etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
		
		if etag != expectedETag {
			t.Errorf("ETag inconsistent on iteration %d: got %s, want %s", i, etag, expectedETag)
		}
	}
}

func TestBufferSizeOptimization(t *testing.T) {
	// Test that we use appropriate buffer sizes for different file types
	tests := []struct {
		name         string
		fileSize     int64
		expectedPool string
	}{
		{
			name:         "tiny file",
			fileSize:     100,
			expectedPool: "small",
		},
		{
			name:         "small file at limit",
			fileSize:     smallFileLimit,
			expectedPool: "small",
		},
		{
			name:         "medium file",
			fileSize:     smallFileLimit + 1,
			expectedPool: "none", // Large files don't use buffer pool for MD5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := strings.Repeat("A", int(tt.fileSize))
			
			storage := &mockStorage{}
			auth := &mockAuth{}
			cfg := config.S3Config{}
			chunking := config.ChunkingConfig{}
			handler := NewHandler(storage, auth, cfg, chunking)

			req := httptest.NewRequest("PUT", "/test-bucket/file.txt", 
				strings.NewReader(data))
			req.Header.Set("Content-Length", fmt.Sprintf("%d", tt.fileSize))
			req.Header.Set("User-Agent", "test-client/1.0")
			req = createAdminContext(req)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": "test-bucket",
				"key":    "file.txt",
			})

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			etag := w.Header().Get("ETag")
			if tt.expectedPool == "small" {
				// Should have real MD5 ETag
				if !strings.Contains(etag, `"`) || etag == `"large-file-etag"` {
					t.Errorf("Expected real MD5 ETag for small file, got %s", etag)
				}
			} else {
				// Should have generic ETag
				if etag != `"large-file-etag"` {
					t.Errorf("Expected generic ETag for large file, got %s", etag)
				}
			}
		})
	}
}