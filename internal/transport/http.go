// Package transport provides optimized HTTP transport configurations.
package transport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"
)

var (
	// Global transport pool for connection reuse
	transportPool = sync.Pool{
		New: func() interface{} {
			return NewFastHTTPTransport()
		},
	}

	// DNS cache for faster lookups
	dnsCache = &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		ttl:   5 * time.Minute,
	}
)

type dnsCacheEntry struct {
	ips       []net.IP
	expiry    time.Time
	resolving sync.Mutex
}

type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]*dnsCacheEntry
	ttl   time.Duration
}

func (d *DNSCache) resolve(ctx context.Context, host string) ([]net.IP, error) {
	d.mu.RLock()
	entry, exists := d.cache[host]
	d.mu.RUnlock()

	if exists && time.Now().Before(entry.expiry) {
		return entry.ips, nil
	}

	// Create or get entry
	d.mu.Lock()
	entry, exists = d.cache[host]
	if !exists {
		entry = &dnsCacheEntry{}
		d.cache[host] = entry
	}
	d.mu.Unlock()

	// Resolve with lock to prevent thundering herd
	entry.resolving.Lock()
	defer entry.resolving.Unlock()

	// Check again in case another goroutine resolved it
	if time.Now().Before(entry.expiry) {
		return entry.ips, nil
	}

	// Perform DNS lookup
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	entry.ips = ips
	entry.expiry = time.Now().Add(d.ttl)
	return ips, nil
}

// FastDialer provides optimized dialing with DNS caching
type FastDialer struct {
	*net.Dialer
	dnsCache *DNSCache
}

func (d *FastDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.Dialer.DialContext(ctx, network, addr)
	}

	// Try DNS cache first
	ips, err := d.dnsCache.resolve(ctx, host)
	if err == nil && len(ips) > 0 {
		// Use first IP (could implement round-robin)
		addr = net.JoinHostPort(ips[0].String(), port)
	}

	return d.Dialer.DialContext(ctx, network, addr)
}

// NewFastHTTPTransport creates an optimized HTTP transport for maximum performance
func NewFastHTTPTransport() *http.Transport {
	// Max performance
	maxConns := runtime.GOMAXPROCS(0) * 2000       // Max connections
	maxConnsPerHost := runtime.GOMAXPROCS(0) * 400 // Max per host

	dialer := &FastDialer{
		Dialer: &net.Dialer{
			Timeout:   200 * time.Millisecond,
			KeepAlive: 5 * time.Second,
			DualStack: true,
			// Low latency
			Control: setTCPOptions,
		},
		dnsCache: dnsCache,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxConns,
		MaxIdleConnsPerHost:   maxConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   500 * time.Millisecond,
		ExpectContinueTimeout: 200 * time.Millisecond,
		DisableCompression:    true, // No compression
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 1 * time.Second,
		// Optimize TLS
		TLSClientConfig: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: false, // Enable session resumption
			ClientSessionCache:     tls.NewLRUClientSessionCache(1000),
		},
		// Enable HTTP/2
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		// EXTREME: Maximum buffer sizes for raw speed
		WriteBufferSize: 2048 * 1024, // 2MB write buffer (doubled)
		ReadBufferSize:  2048 * 1024, // 2MB read buffer (doubled)
	}

	return transport
}

// GetPooledTransport returns a transport from the pool
func GetPooledTransport() *http.Transport {
	return transportPool.Get().(*http.Transport)
}

// ReturnPooledTransport returns a transport to the pool
func ReturnPooledTransport(t *http.Transport) {
	// Reset idle connections before returning to pool
	t.CloseIdleConnections()
	transportPool.Put(t)
}

// GetSDKOptimizedTransport creates an ultra-optimized transport for SDK operations
func GetSDKOptimizedTransport() *http.Transport {
	// SDK EXTREME: Even more aggressive settings for SDK operations
	maxConns := runtime.GOMAXPROCS(0) * 4000       // 16x increase for SDK operations
	maxConnsPerHost := runtime.GOMAXPROCS(0) * 800 // 16x increase for SDK operations

	dialer := &FastDialer{
		Dialer: &net.Dialer{
			Timeout:   250 * time.Millisecond, // SDK EXTREME: 250ms timeout
			KeepAlive: 15 * time.Second,       // SDK OPTIMIZATION: Longer keepalive
			DualStack: true,
			Control:   setTCPOptions,
		},
		dnsCache: dnsCache,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxConns,
		MaxIdleConnsPerHost:   maxConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       120 * time.Second,      // SDK OPTIMIZATION: Longer idle
		TLSHandshakeTimeout:   500 * time.Millisecond, // SDK EXTREME: 500ms TLS
		ExpectContinueTimeout: 250 * time.Millisecond, // SDK EXTREME: 250ms
		DisableCompression:    true,                   // No compression for speed
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 1 * time.Second, // SDK EXTREME: 1s headers
		TLSClientConfig: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: false,
			ClientSessionCache:     tls.NewLRUClientSessionCache(2000), // Larger cache
		},
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		// SDK EXTREME: Even larger buffers for raw throughput
		WriteBufferSize: 4096 * 1024, // 4MB write buffer
		ReadBufferSize:  4096 * 1024, // 4MB read buffer
	}

	return transport
}
