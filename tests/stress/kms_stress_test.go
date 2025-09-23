//go:build stress
// +build stress

package stress

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"
)

// Test configuration
type StressConfig struct {
	ProxyEndpoint  string
	Concurrency    int
	Duration       time.Duration
	ObjectSizeMin  int
	ObjectSizeMax  int
	ReadWriteRatio float64 // 0.0 = all writes, 1.0 = all reads
	BucketRotation int     // Number of buckets to rotate through
}

// Metrics collection
type Metrics struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	BytesWritten       int64
	BytesRead          int64
	WriteLatencies     []time.Duration
	ReadLatencies      []time.Duration
	KMSOperations      int64
	mu                 sync.Mutex
}

func (m *Metrics) RecordWrite(duration time.Duration, bytes int64, success bool) {
	atomic.AddInt64(&m.TotalRequests, 1)
	if success {
		atomic.AddInt64(&m.SuccessfulRequests, 1)
		atomic.AddInt64(&m.BytesWritten, bytes)
		atomic.AddInt64(&m.KMSOperations, 1)
		m.mu.Lock()
		m.WriteLatencies = append(m.WriteLatencies, duration)
		m.mu.Unlock()
	} else {
		atomic.AddInt64(&m.FailedRequests, 1)
	}
}

func (m *Metrics) RecordRead(duration time.Duration, bytes int64, success bool) {
	atomic.AddInt64(&m.TotalRequests, 1)
	if success {
		atomic.AddInt64(&m.SuccessfulRequests, 1)
		atomic.AddInt64(&m.BytesRead, bytes)
		m.mu.Lock()
		m.ReadLatencies = append(m.ReadLatencies, duration)
		m.mu.Unlock()
	} else {
		atomic.AddInt64(&m.FailedRequests, 1)
	}
}

func TestKMSStress(t *testing.T) {
	// Skip if not running stress tests
	if os.Getenv("RUN_STRESS_TESTS") != "true" {
		t.Skip("Skipping stress test. Set RUN_STRESS_TESTS=true to run")
	}

	config := StressConfig{
		ProxyEndpoint:  getEnvOrDefault("PROXY_ENDPOINT", "http://localhost:8080"),
		Concurrency:    getIntEnvOrDefault("STRESS_CONCURRENCY", 50),
		Duration:       getDurationEnvOrDefault("STRESS_DURATION", 5*time.Minute),
		ObjectSizeMin:  getIntEnvOrDefault("OBJECT_SIZE_MIN", 1024),     // 1KB
		ObjectSizeMax:  getIntEnvOrDefault("OBJECT_SIZE_MAX", 10485760), // 10MB
		ReadWriteRatio: getFloatEnvOrDefault("READ_WRITE_RATIO", 0.5),   // 50/50
		BucketRotation: getIntEnvOrDefault("BUCKET_ROTATION", 3),
	}

	// Initialize S3 client
	sess, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(config.ProxyEndpoint),
		Region:           aws.String("us-east-1"),
		Credentials:      credentials.NewStaticCredentials("admin", "secret", ""),
		S3ForcePathStyle: aws.Bool(true),
		DisableSSL:       aws.Bool(true),
	})
	require.NoError(t, err)

	client := s3.New(sess)
	metrics := &Metrics{}

	// Test buckets
	buckets := []string{"internal-data", "sensitive-data", "financial-data"}

	// Create worker pool
	ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(config.Concurrency)

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			runWorker(ctx, workerID, client, buckets, config, metrics)
		}(i)
	}

	// Monitor progress
	go monitorProgress(ctx, metrics)

	// Wait for completion
	wg.Wait()

	// Print final report
	printReport(metrics, config)
}

func runWorker(ctx context.Context, workerID int, client *s3.S3, buckets []string, config StressConfig, metrics *Metrics) {
	objectCount := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Select bucket
			bucket := buckets[objectCount%len(buckets)]
			objectCount++

			// Decide operation type
			if mathrand.Float64() < config.ReadWriteRatio && objectCount > 10 {
				// Read operation
				performRead(client, bucket, workerID, objectCount-10, metrics)
			} else {
				// Write operation
				size := config.ObjectSizeMin + mathrand.Intn(config.ObjectSizeMax-config.ObjectSizeMin)
				performWrite(client, bucket, workerID, objectCount, size, metrics)
			}

			// Small delay to prevent overwhelming
			time.Sleep(time.Millisecond * 10)
		}
	}
}

func performWrite(client *s3.S3, bucket string, workerID, objectID, size int, metrics *Metrics) {
	key := fmt.Sprintf("worker-%d/object-%d", workerID, objectID)
	data := make([]byte, size)
	rand.Read(data)

	start := time.Now()
	_, err := client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
		Metadata: map[string]*string{
			"worker-id": aws.String(fmt.Sprintf("%d", workerID)),
			"object-id": aws.String(fmt.Sprintf("%d", objectID)),
			"test-time": aws.String(time.Now().Format(time.RFC3339)),
		},
		// Request server-side encryption with KMS
		ServerSideEncryption: aws.String("aws:kms"),
	})
	duration := time.Since(start)

	success := err == nil
	if !success {
		fmt.Printf("Write error: %v\n", err)
	}

	metrics.RecordWrite(duration, int64(size), success)
}

func performRead(client *s3.S3, bucket string, workerID, objectID int, metrics *Metrics) {
	key := fmt.Sprintf("worker-%d/object-%d", workerID, objectID)

	start := time.Now()
	resp, err := client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		metrics.RecordRead(time.Since(start), 0, false)
		return
	}
	defer resp.Body.Close()

	// Read the entire object
	written, err := io.Copy(io.Discard, resp.Body)
	duration := time.Since(start)

	success := err == nil
	metrics.RecordRead(duration, written, success)

	// Verify encryption
	if resp.ServerSideEncryption != nil && *resp.ServerSideEncryption == "aws:kms" {
		atomic.AddInt64(&metrics.KMSOperations, 1)
	}
}

func monitorProgress(ctx context.Context, metrics *Metrics) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	lastTotal := int64(0)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total := atomic.LoadInt64(&metrics.TotalRequests)
			successful := atomic.LoadInt64(&metrics.SuccessfulRequests)
			failed := atomic.LoadInt64(&metrics.FailedRequests)
			kmsOps := atomic.LoadInt64(&metrics.KMSOperations)
			bytesWritten := atomic.LoadInt64(&metrics.BytesWritten)
			bytesRead := atomic.LoadInt64(&metrics.BytesRead)

			rps := float64(total-lastTotal) / 10.0
			lastTotal = total

			fmt.Printf("[%s] Requests: %d (%.1f/s), Success: %d, Failed: %d, KMS Ops: %d, Written: %s, Read: %s\n",
				time.Now().Format("15:04:05"),
				total, rps, successful, failed, kmsOps,
				formatBytes(bytesWritten), formatBytes(bytesRead))
		}
	}
}

func printReport(metrics *Metrics, config StressConfig) {
	fmt.Println("\n=== Stress Test Report ===")
	fmt.Printf("Duration: %v\n", config.Duration)
	fmt.Printf("Concurrency: %d\n", config.Concurrency)
	fmt.Printf("Total Requests: %d\n", metrics.TotalRequests)
	fmt.Printf("Successful: %d (%.2f%%)\n", metrics.SuccessfulRequests,
		float64(metrics.SuccessfulRequests)/float64(metrics.TotalRequests)*100)
	fmt.Printf("Failed: %d\n", metrics.FailedRequests)
	fmt.Printf("KMS Operations: %d\n", metrics.KMSOperations)
	fmt.Printf("Data Written: %s\n", formatBytes(metrics.BytesWritten))
	fmt.Printf("Data Read: %s\n", formatBytes(metrics.BytesRead))

	// Calculate latency percentiles
	if len(metrics.WriteLatencies) > 0 {
		fmt.Println("\nWrite Latencies:")
		printLatencyStats(metrics.WriteLatencies)
	}

	if len(metrics.ReadLatencies) > 0 {
		fmt.Println("\nRead Latencies:")
		printLatencyStats(metrics.ReadLatencies)
	}

	// Calculate throughput
	totalBytes := metrics.BytesWritten + metrics.BytesRead
	throughput := float64(totalBytes) / config.Duration.Seconds()
	fmt.Printf("\nThroughput: %s/s\n", formatBytes(int64(throughput)))
}

func printLatencyStats(latencies []time.Duration) {
	// Sort latencies
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)

	// Simple bubble sort for demonstration
	for i := 0; i < len(sorted); i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			if sorted[j] > sorted[j+1] {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	p50 := sorted[len(sorted)*50/100]
	p95 := sorted[len(sorted)*95/100]
	p99 := sorted[len(sorted)*99/100]

	fmt.Printf("  P50: %v\n", p50)
	fmt.Printf("  P95: %v\n", p95)
	fmt.Printf("  P99: %v\n", p99)
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnvOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		fmt.Sscanf(value, "%d", &result)
		return result
	}
	return defaultValue
}

func getFloatEnvOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		var result float64
		fmt.Sscanf(value, "%f", &result)
		return result
	}
	return defaultValue
}

func getDurationEnvOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
