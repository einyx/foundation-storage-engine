package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/einyx/s3proxy-go/internal/config"
	"github.com/einyx/s3proxy-go/internal/proxy"
)

func BenchmarkS3ProxyGet(b *testing.B) {
	// Create test server with optimized settings
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  30 * time.Second,   // Reduced timeout for faster tests
			WriteTimeout: 30 * time.Second,   // Reduced timeout for faster tests
			IdleTimeout:  60 * time.Second,   // Reduced timeout for faster tests
			MaxBodySize:  1024 * 1024 * 1024, // 1GB
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: b.TempDir(),
			},
		},
	}

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(proxyServer)
	defer ts.Close()

	// Create optimized HTTP client for benchmarking
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
		},
		Timeout: 30 * time.Second,
	}

	// Create test data with various sizes for real-world testing
	sizes := []int{
		1024,              // 1KB - small objects
		64 * 1024,         // 64KB - medium objects
		1024 * 1024,       // 1MB - large objects
		10 * 1024 * 1024,  // 10MB - very large objects
		100 * 1024 * 1024, // 100MB - huge objects
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%dB", size), func(b *testing.B) {
			// Create test object with random data
			data := make([]byte, size)
			_, _ = rand.Read(data)

			// Upload object once
			req, _ := http.NewRequestWithContext(context.Background(), "PUT", ts.URL+"/test-bucket/test-object", bytes.NewReader(data))
			req.ContentLength = int64(size)
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			_ = resp.Body.Close()

			b.ResetTimer()
			b.SetBytes(int64(size))

			// Benchmark GET requests with realistic parallelism
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/test-bucket/test-object", nil)
					resp, err := client.Do(req)
					if err != nil {
						b.Fatal(err)
					}

					// Use efficient discard to avoid memory allocation
					written, err := io.Copy(io.Discard, resp.Body)
					if err != nil {
						b.Fatal(err)
					}
					if written != int64(size) {
						b.Fatalf("Expected %d bytes, got %d", size, written)
					}
					_ = resp.Body.Close()
				}
			})
		})
	}
}

func BenchmarkS3ProxyPut(b *testing.B) {
	// Create test server
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: b.TempDir(),
			},
		},
	}

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(proxyServer)
	defer ts.Close()

	// Create test bucket
	req, _ := http.NewRequestWithContext(context.Background(), "PUT", ts.URL+"/test-bucket", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}

	sizes := []int{
		1024,             // 1KB
		1024 * 1024,      // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			_, _ = rand.Read(data)

			b.ResetTimer()
			b.SetBytes(int64(size))

			// Benchmark PUT requests
			for i := 0; i < b.N; i++ {
				req, _ := http.NewRequestWithContext(
					context.Background(), "PUT", ts.URL+fmt.Sprintf("/test-bucket/object-%d", i), bytes.NewReader(data),
				)
				req.ContentLength = int64(size)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				_ = resp.Body.Close()
			}
		})
	}
}

func BenchmarkAuthentication(b *testing.B) {
	// Create test server with fast auth
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		Auth: config.AuthConfig{
			Type:       "awsv4",
			Identity:   "test-access-key",
			Credential: "test-secret-key",
		},
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: b.TempDir(),
			},
		},
	}

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	handler := proxyServer.ServeHTTP

	b.ResetTimer()

	// Benchmark authentication overhead
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test-bucket", nil)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test-access-key/20240101/us-east-1/s3/aws4_request")
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

func BenchmarkConcurrentRequests(b *testing.B) {
	// Create test server with high-performance settings
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
			MaxBodySize:  1024 * 1024 * 1024, // 1GB
		},
		Auth: config.AuthConfig{
			Type: "none",
		},
		Storage: config.StorageConfig{
			Provider: "filesystem",
			FileSystem: &config.FileSystemConfig{
				BaseDir: b.TempDir(),
			},
		},
	}

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(proxyServer)
	defer ts.Close()

	// Create test data with varying sizes
	sizes := []int{
		64 * 1024,        // 64KB
		1024 * 1024,      // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("concurrent_size_%dB", size), func(b *testing.B) {
			data := make([]byte, size)
			_, _ = rand.Read(data)

			// Upload test object
			req, _ := http.NewRequestWithContext(context.Background(), "PUT", ts.URL+"/test-bucket/test-object", bytes.NewReader(data))
			req.ContentLength = int64(size)
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			_ = resp.Body.Close()

			b.ResetTimer()
			b.SetBytes(int64(size))

			// Benchmark highly concurrent requests
			b.RunParallel(func(pb *testing.PB) {
				// Each goroutine gets its own optimized client
				client := &http.Client{
					Transport: &http.Transport{
						MaxIdleConnsPerHost: 50,
						MaxConnsPerHost:     50,
						IdleConnTimeout:     30 * time.Second,
						DisableCompression:  true,
						DisableKeepAlives:   false,
					},
					Timeout: 30 * time.Second,
				}

				for pb.Next() {
					req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/test-bucket/test-object", nil)
					resp, err := client.Do(req)
					if err != nil {
						b.Fatal(err)
					}

					written, err := io.Copy(io.Discard, resp.Body)
					if err != nil {
						b.Fatal(err)
					}
					if written != int64(size) {
						b.Fatalf("Expected %d bytes, got %d", size, written)
					}
					_ = resp.Body.Close()
				}
			})
		})
	}
}

// BenchmarkRangeRequests tests the performance of HTTP range requests
func BenchmarkRangeRequests(b *testing.B) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Auth: config.AuthConfig{Type: "none"},
		Storage: config.StorageConfig{
			Provider:   "filesystem",
			FileSystem: &config.FileSystemConfig{BaseDir: b.TempDir()},
		},
	}

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(proxyServer)
	defer ts.Close()

	// Create a large test object
	size := 100 * 1024 * 1024 // 100MB
	data := make([]byte, size)
	_, _ = rand.Read(data)

	client := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), "PUT", ts.URL+"/test-bucket/large-object", bytes.NewReader(data))
	req.ContentLength = int64(size)
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	_ = resp.Body.Close()

	b.ResetTimer()

	// Test various range sizes
	rangeSizes := []int{
		1024 * 1024,      // 1MB chunks
		10 * 1024 * 1024, // 10MB chunks
		50 * 1024 * 1024, // 50MB chunks
	}

	for _, rangeSize := range rangeSizes {
		b.Run(fmt.Sprintf("range_%dB", rangeSize), func(b *testing.B) {
			b.SetBytes(int64(rangeSize))

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					// Random range request within the file
					start := mathrand.Intn(size - rangeSize)
					end := start + rangeSize - 1

					req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/test-bucket/large-object", nil)
					req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

					resp, err := client.Do(req)
					if err != nil {
						b.Fatal(err)
					}

					if resp.StatusCode != 206 {
						b.Fatalf("Expected 206 Partial Content, got %d", resp.StatusCode)
					}

					written, err := io.Copy(io.Discard, resp.Body)
					if err != nil {
						b.Fatal(err)
					}
					if written != int64(rangeSize) {
						b.Fatalf("Expected %d bytes, got %d", rangeSize, written)
					}
					_ = resp.Body.Close()
				}
			})
		})
	}
}

// BenchmarkMetricsOverhead tests the performance impact of metrics collection
func BenchmarkMetricsOverhead(b *testing.B) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Auth: config.AuthConfig{Type: "none"},
		Storage: config.StorageConfig{
			Provider:   "filesystem",
			FileSystem: &config.FileSystemConfig{BaseDir: b.TempDir()},
		},
	}

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(proxyServer)
	defer ts.Close()

	// Small object for minimal I/O overhead
	size := 1024 // 1KB
	data := make([]byte, size)
	_, _ = rand.Read(data)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), "PUT", ts.URL+"/test-bucket/small-object", bytes.NewReader(data))
	req.ContentLength = int64(size)
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	_ = resp.Body.Close()

	b.ResetTimer()
	b.SetBytes(int64(size))

	// Test pure request throughput to measure metrics overhead
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/test-bucket/small-object", nil)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
