package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func main() {
	// Start CPU profiling
	cpuFile, err := os.Create("cpu.prof")
	if err != nil {
		log.Fatal(err)
	}
	defer cpuFile.Close()
	
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		log.Fatal(err)
	}
	defer pprof.StopCPUProfile()

	// Configure S3 client
	endpoint := os.Getenv("S3_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://s3.dev.meshx.dev"
	}
	
	accessKey := os.Getenv("S3_ACCESS_KEY")
	if accessKey == "" {
		log.Fatal("S3_ACCESS_KEY environment variable is required")
	}
	
	secretKey := os.Getenv("S3_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("S3_SECRET_KEY environment variable is required")
	}
	
	sess, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(endpoint),
		Region:           aws.String("us-east-1"),
		Credentials:      credentials.NewStaticCredentials(accessKey, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		DisableSSL:       aws.Bool(false),
	})
	if err != nil {
		log.Fatal(err)
	}

	svc := s3.New(sess)

	// Test different file sizes
	sizes := []int{
		1 * 1024 * 1024,   // 1MB
		5 * 1024 * 1024,   // 5MB
		10 * 1024 * 1024,  // 10MB
		50 * 1024 * 1024,  // 50MB
		100 * 1024 * 1024, // 100MB
	}

	for _, size := range sizes {
		fmt.Printf("\nTesting %d MB upload...\n", size/(1024*1024))
		
		// Print memory stats before
		printMemStats("Before upload")
		
		// Generate random data
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			log.Printf("Failed to generate random data: %v", err)
			continue
		}
		
		// Upload the data
		start := time.Now()
		key := fmt.Sprintf("memtest-%d.bin", size)
		
		_, err := svc.PutObject(&s3.PutObjectInput{
			Bucket:        aws.String("warehouse"),
			Key:           aws.String(key),
			Body:          bytes.NewReader(data),
			ContentLength: aws.Int64(int64(size)),
		})
		
		if err != nil {
			log.Printf("Upload failed: %v", err)
			continue
		}
		
		duration := time.Since(start)
		throughput := float64(size) / duration.Seconds() / 1024 / 1024
		
		fmt.Printf("Upload completed in %v (%.2f MB/s)\n", duration, throughput)
		
		// Print memory stats after
		printMemStats("After upload")
		
		// Force GC and print stats again
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		printMemStats("After GC")
		
		// Cleanup
		_, _ = svc.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String("warehouse"),
			Key:    aws.String(key),
		})
	}

	// Write memory profile
	memFile, err := os.Create("mem.prof")
	if err != nil {
		log.Fatal(err)
	}
	defer memFile.Close()
	
	runtime.GC()
	if err := pprof.WriteHeapProfile(memFile); err != nil {
		log.Fatal(err)
	}
	
	fmt.Println("\nProfiling complete. Use 'go tool pprof' to analyze cpu.prof and mem.prof")
}

func printMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	fmt.Printf("%s:\n", label)
	fmt.Printf("  Alloc: %.2f MB\n", float64(m.Alloc)/1024/1024)
	fmt.Printf("  TotalAlloc: %.2f MB\n", float64(m.TotalAlloc)/1024/1024)
	fmt.Printf("  Sys: %.2f MB\n", float64(m.Sys)/1024/1024)
	fmt.Printf("  NumGC: %d\n", m.NumGC)
	fmt.Printf("  HeapAlloc: %.2f MB\n", float64(m.HeapAlloc)/1024/1024)
	fmt.Printf("  HeapInuse: %.2f MB\n", float64(m.HeapInuse)/1024/1024)
	fmt.Printf("  HeapObjects: %d\n", m.HeapObjects)
}