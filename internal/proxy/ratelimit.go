// Package proxy provides HTTP proxy server implementation with rate limiting.
package proxy

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides request rate limiting
type RateLimiter struct {
	global    *rate.Limiter
	perIP     map[string]*ipLimiter
	mu        sync.RWMutex
	cleanupMu sync.Mutex
	maxBurst  int
}

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(globalRPS, _ float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		global:   rate.NewLimiter(rate.Limit(globalRPS), burst),
		perIP:    make(map[string]*ipLimiter),
		maxBurst: burst,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanupMu.Lock()
		rl.mu.Lock()

		now := time.Now()
		for ip, limiter := range rl.perIP {
			if now.Sub(limiter.lastSeen) > 5*time.Minute {
				delete(rl.perIP, ip)
			}
		}

		rl.mu.Unlock()
		rl.cleanupMu.Unlock()
	}
}

func (rl *RateLimiter) getLimiter(ip string, perIPRPS float64) *rate.Limiter {
	rl.mu.RLock()
	ipL, exists := rl.perIP[ip]
	rl.mu.RUnlock()

	if exists {
		ipL.lastSeen = time.Now()
		return ipL.limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check again with write lock
	if ipL, exists := rl.perIP[ip]; exists {
		ipL.lastSeen = time.Now()
		return ipL.limiter
	}

	// Create new limiter
	limiter := rate.NewLimiter(rate.Limit(perIPRPS), rl.maxBurst)
	rl.perIP[ip] = &ipLimiter{
		limiter:  limiter,
		lastSeen: time.Now(),
	}

	return limiter
}

// Middleware returns a middleware that enforces rate limits
func (rl *RateLimiter) Middleware(perIPRPS float64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Global rate limit
			if !rl.global.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Per-IP rate limit
			ip := getClientIP(r)
			ipLimiter := rl.getLimiter(ip, perIPRPS)

			if !ipLimiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ConcurrencyLimiter limits concurrent requests
type ConcurrencyLimiter struct {
	semaphore chan struct{}
}

// NewConcurrencyLimiter creates a new concurrency limiter
func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		semaphore: make(chan struct{}, maxConcurrent),
	}
}

// Middleware returns a middleware that limits concurrent requests
func (cl *ConcurrencyLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			select {
			case cl.semaphore <- struct{}{}:
				defer func() { <-cl.semaphore }()
				next.ServeHTTP(w, r)
			case <-ctx.Done():
				http.Error(w, "Request timeout", http.StatusRequestTimeout)
			default:
				http.Error(w, "Server too busy", http.StatusServiceUnavailable)
			}
		})
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if comma := indexOf(xff, ','); comma != -1 {
			return xff[:comma]
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if colon := lastIndexOf(r.RemoteAddr, ':'); colon != -1 {
		return r.RemoteAddr[:colon]
	}

	return r.RemoteAddr
}

func indexOf(s string, c rune) int {
	for i, r := range s {
		if r == c {
			return i
		}
	}
	return -1
}

func lastIndexOf(s string, c rune) int {
	for i := len(s) - 1; i >= 0; i-- {
		if rune(s[i]) == c {
			return i
		}
	}
	return -1
}
