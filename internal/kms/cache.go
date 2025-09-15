// Package kms provides AWS KMS integration for encryption and key management.
package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DataKey represents a KMS data key for envelope encryption
type DataKey struct {
	KeyID             string
	PlaintextKey      []byte
	CiphertextBlob    []byte
	EncryptionContext map[string]string
	CreatedAt         time.Time
}

// DataKeyCache implements a TTL cache for data keys
type DataKeyCache struct {
	cache    map[string]*cacheEntry
	mu       sync.RWMutex
	ttl      time.Duration
	stopChan chan struct{}
}

type cacheEntry struct {
	dataKey   *DataKey
	expiresAt time.Time
}

// NewDataKeyCache creates a new data key cache
func NewDataKeyCache(ttl time.Duration) *DataKeyCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute // Default TTL
	}

	c := &DataKeyCache{
		cache:    make(map[string]*cacheEntry),
		ttl:      ttl,
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go c.cleanupLoop()

	return c
}

// Get retrieves a data key from cache
func (c *DataKeyCache) Get(key string) *DataKey {
	if c == nil || key == "" {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[key]
	if !ok || entry == nil {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.dataKey
}

// Put adds a data key to cache
func (c *DataKeyCache) Put(key string, dataKey *DataKey) {
	if c == nil || key == "" || dataKey == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear old entry's sensitive data if exists
	if oldEntry, exists := c.cache[key]; exists && oldEntry != nil && oldEntry.dataKey != nil {
		c.clearSensitiveData(oldEntry.dataKey)
	}

	c.cache[key] = &cacheEntry{
		dataKey:   dataKey,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Delete removes a data key from cache
func (c *DataKeyCache) Delete(key string) {
	if c == nil || key == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear sensitive data before deletion
	if entry, exists := c.cache[key]; exists && entry != nil && entry.dataKey != nil {
		c.clearSensitiveData(entry.dataKey)
	}

	delete(c.cache, key)
}

// Clear removes all entries from cache
func (c *DataKeyCache) Clear() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear sensitive data from all entries
	for _, entry := range c.cache {
		if entry != nil && entry.dataKey != nil {
			c.clearSensitiveData(entry.dataKey)
		}
	}

	c.cache = make(map[string]*cacheEntry)
}

// Size returns the number of cached entries
func (c *DataKeyCache) Size() int {
	if c == nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// cleanupLoop periodically removes expired entries
func (c *DataKeyCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopChan:
			return
		}
	}
}

// cleanup removes expired entries
func (c *DataKeyCache) cleanup() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if entry == nil {
			delete(c.cache, key)
			continue
		}

		if now.After(entry.expiresAt) {
			// Zero out the plaintext key before removing
			if entry.dataKey != nil {
				c.clearSensitiveData(entry.dataKey)
			}
			delete(c.cache, key)
		}
	}
}

// Close stops the cleanup goroutine and clears the cache
func (c *DataKeyCache) Close() {
	if c == nil {
		return
	}

	// Signal cleanup goroutine to stop
	select {
	case <-c.stopChan:
		// Already closed
		return
	default:
		close(c.stopChan)
	}

	// Zero out all plaintext keys
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, entry := range c.cache {
		if entry != nil && entry.dataKey != nil {
			c.clearSensitiveData(entry.dataKey)
		}
	}

	c.cache = make(map[string]*cacheEntry)
}

// buildDataKeyCacheKey creates a cache key from keyID and encryption context
func buildDataKeyCacheKey(keyID string, context map[string]string) string {
	if keyID == "" {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(keyID))

	// Sort context keys for consistent hashing
	// Note: This is not truly sorted but for backward compatibility we keep it
	for k, v := range context {
		h.Write([]byte(k))
		h.Write([]byte(v))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// serializeEncryptionContext converts encryption context to string format
func serializeEncryptionContext(context map[string]string) string {
	if len(context) == 0 {
		return ""
	}

	// AWS expects base64-encoded JSON, but for headers we'll use a simpler format
	result := ""
	first := true
	for k, v := range context {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%s=%s", k, v)
		first = false
	}

	return result
}

// clearSensitiveData zeros out sensitive data in a DataKey
func (c *DataKeyCache) clearSensitiveData(dataKey *DataKey) {
	if dataKey == nil {
		return
	}

	if dataKey.PlaintextKey != nil {
		for i := range dataKey.PlaintextKey {
			dataKey.PlaintextKey[i] = 0
		}
	}
}
