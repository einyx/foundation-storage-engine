package transport

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func TestNewFastHTTPTransport(t *testing.T) {
	transport := NewFastHTTPTransport()

	if transport == nil {
		t.Fatal("NewFastHTTPTransport returned nil")
	}

	// Test connection limits
	expectedMaxConns := runtime.GOMAXPROCS(0) * 2000
	expectedMaxConnsPerHost := runtime.GOMAXPROCS(0) * 400

	if transport.MaxIdleConns != expectedMaxConns {
		t.Errorf("Expected MaxIdleConns %d, got %d", expectedMaxConns, transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != expectedMaxConnsPerHost {
		t.Errorf("Expected MaxIdleConnsPerHost %d, got %d", expectedMaxConnsPerHost, transport.MaxIdleConnsPerHost)
	}

	// Test timeouts
	if transport.IdleConnTimeout != 90*time.Second {
		t.Errorf("Expected IdleConnTimeout 90s, got %v", transport.IdleConnTimeout)
	}

	if transport.TLSHandshakeTimeout != 500*time.Millisecond {
		t.Errorf("Expected TLSHandshakeTimeout 500ms, got %v", transport.TLSHandshakeTimeout)
	}

	// Test buffer sizes
	if transport.WriteBufferSize != 2048*1024 {
		t.Errorf("Expected WriteBufferSize 2MB, got %d", transport.WriteBufferSize)
	}

	if transport.ReadBufferSize != 2048*1024 {
		t.Errorf("Expected ReadBufferSize 2MB, got %d", transport.ReadBufferSize)
	}

	// Test compression is disabled
	if !transport.DisableCompression {
		t.Error("Expected compression to be disabled")
	}

	// Test keep-alives are enabled
	if transport.DisableKeepAlives {
		t.Error("Expected keep-alives to be enabled")
	}

	// Test HTTP/2 is enabled
	if !transport.ForceAttemptHTTP2 {
		t.Error("Expected HTTP/2 to be enabled")
	}
}

func TestGetSDKOptimizedTransport(t *testing.T) {
	transport := GetSDKOptimizedTransport()

	if transport == nil {
		t.Fatal("GetSDKOptimizedTransport returned nil")
	}

	// Test aggressive connection limits for SDK
	expectedMaxConns := runtime.GOMAXPROCS(0) * 4000
	expectedMaxConnsPerHost := runtime.GOMAXPROCS(0) * 800

	if transport.MaxIdleConns != expectedMaxConns {
		t.Errorf("Expected MaxIdleConns %d, got %d", expectedMaxConns, transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != expectedMaxConnsPerHost {
		t.Errorf("Expected MaxIdleConnsPerHost %d, got %d", expectedMaxConnsPerHost, transport.MaxIdleConnsPerHost)
	}

	// Test SDK-specific timeouts
	if transport.IdleConnTimeout != 120*time.Second {
		t.Errorf("Expected IdleConnTimeout 120s, got %v", transport.IdleConnTimeout)
	}

	if transport.ExpectContinueTimeout != 250*time.Millisecond {
		t.Errorf("Expected ExpectContinueTimeout 250ms, got %v", transport.ExpectContinueTimeout)
	}

	// Test larger buffer sizes for SDK
	if transport.WriteBufferSize != 4096*1024 {
		t.Errorf("Expected WriteBufferSize 4MB, got %d", transport.WriteBufferSize)
	}

	if transport.ReadBufferSize != 4096*1024 {
		t.Errorf("Expected ReadBufferSize 4MB, got %d", transport.ReadBufferSize)
	}
}

func TestGetPooledTransport(t *testing.T) {
	transport := GetPooledTransport()
	if transport == nil {
		t.Fatal("GetPooledTransport returned nil")
	}

	// Verify it's a valid transport
	if transport.MaxIdleConns == 0 {
		t.Error("Transport should have MaxIdleConns set")
	}
}

func TestReturnPooledTransport(t *testing.T) {
	transport := GetPooledTransport()
	if transport == nil {
		t.Fatal("GetPooledTransport returned nil")
	}

	// This should not panic
	ReturnPooledTransport(transport)

	// Get another transport from pool
	transport2 := GetPooledTransport()
	if transport2 == nil {
		t.Fatal("Second GetPooledTransport returned nil")
	}
}

func TestDNSCache_resolve(t *testing.T) {
	cache := &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   5 * time.Minute,
	}

	ctx := context.Background()

	// Test resolving a real hostname
	ips, err := cache.resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("Failed to resolve localhost: %v", err)
	}

	if len(ips) == 0 {
		t.Error("Expected at least one IP for localhost")
	}

	// Test cache hit
	ips2, err := cache.resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("Failed to resolve localhost from cache: %v", err)
	}

	if len(ips2) != len(ips) {
		t.Error("Cache should return same number of IPs")
	}

	// Verify entry exists in cache
	cache.mu.RLock()
	entry, exists := cache.cache["localhost"]
	cache.mu.RUnlock()

	if !exists {
		t.Error("Expected cache entry for localhost")
	}

	if entry == nil {
		t.Error("Cache entry should not be nil")
	}

	if time.Now().After(entry.expiry) {
		t.Error("Cache entry should not be expired")
	}
}

func TestDNSCache_resolve_InvalidHost(t *testing.T) {
	cache := &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   5 * time.Minute,
	}

	ctx := context.Background()

	// Test resolving an invalid hostname
	_, err := cache.resolve(ctx, "invalid-hostname-that-should-not-exist.invalid")
	if err == nil {
		t.Error("Expected error for invalid hostname")
	}
}

func TestDNSCache_resolve_Concurrent(t *testing.T) {
	cache := &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   5 * time.Minute,
	}

	ctx := context.Background()
	host := "localhost"

	// Run concurrent resolutions
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := cache.resolve(ctx, host)
			if err != nil {
				t.Errorf("Concurrent resolve failed: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify only one cache entry exists
	cache.mu.RLock()
	if len(cache.cache) != 1 {
		t.Errorf("Expected 1 cache entry, got %d", len(cache.cache))
	}
	cache.mu.RUnlock()
}

func TestFastDialer_DialContext(t *testing.T) {
	dialer := &FastDialer{
		Dialer: &net.Dialer{
			Timeout: 1 * time.Second,
		},
		dnsCache: &DNSCache{
			cache: make(map[string]*dnsCacheEntry),
			ttl:   5 * time.Minute,
		},
	}

	ctx := context.Background()

	// Test dialing to a local address
	// We'll use an invalid port to avoid actually connecting
	conn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:99999")
	if err == nil {
		conn.Close()
		t.Error("Expected connection to fail to invalid port")
	}

	// Test with invalid address format
	_, err = dialer.DialContext(ctx, "tcp", "invalid-address")
	if err == nil {
		t.Error("Expected error for invalid address format")
	}
}

func TestFastDialer_DialContext_WithDNSCache(t *testing.T) {
	cache := &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   5 * time.Minute,
	}

	// Pre-populate cache with localhost
	ctx := context.Background()
	ips, err := cache.resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("Failed to populate cache: %v", err)
	}

	dialer := &FastDialer{
		Dialer: &net.Dialer{
			Timeout: 1 * time.Second,
		},
		dnsCache: cache,
	}

	// This should use the cached DNS result
	_, err = dialer.DialContext(ctx, "tcp", "localhost:99999")
	if err == nil {
		t.Error("Expected connection to fail to invalid port")
	}

	// Verify the cache was used (no additional entries should be created)
	cache.mu.RLock()
	entries := len(cache.cache)
	cache.mu.RUnlock()

	if entries != 1 {
		t.Errorf("Expected 1 cache entry, got %d", entries)
	}

	// Verify the IPs are still the same
	newIps, err := cache.resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("Failed to resolve from cache: %v", err)
	}

	if len(newIps) != len(ips) {
		t.Error("Cache should return consistent results")
	}
}

func TestDNSCache_ExpiredEntry(t *testing.T) {
	cache := &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   1 * time.Millisecond, // Very short TTL
	}

	ctx := context.Background()

	// Resolve once
	_, err := cache.resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("Failed to resolve localhost: %v", err)
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Resolve again - should trigger new lookup
	_, err = cache.resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("Failed to resolve localhost after expiry: %v", err)
	}
}

func TestTransportPool_Lifecycle(t *testing.T) {
	// Test getting and returning multiple transports
	transports := make([]*http.Transport, 5)

	// Get multiple transports
	for i := 0; i < 5; i++ {
		transports[i] = GetPooledTransport()
		if transports[i] == nil {
			t.Fatalf("GetPooledTransport %d returned nil", i)
		}
	}

	// Return them all
	for i := 0; i < 5; i++ {
		ReturnPooledTransport(transports[i])
	}

	// Get another one to ensure pool is working
	transport := GetPooledTransport()
	if transport == nil {
		t.Fatal("GetPooledTransport after returns returned nil")
	}

	ReturnPooledTransport(transport)
}

func BenchmarkDNSCache_resolve(b *testing.B) {
	cache := &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   5 * time.Minute,
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.resolve(ctx, "localhost")
		}
	})
}

func BenchmarkTransportPool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			transport := GetPooledTransport()
			ReturnPooledTransport(transport)
		}
	})
}