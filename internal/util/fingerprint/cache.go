package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	utls "github.com/refraction-networking/utls"
)

// CacheConfig holds configuration for fingerprint cache
type CacheConfig struct {
	Enabled        bool
	MaxSize        int           // Maximum number of cached specs (default: 1000)
	TTL            time.Duration // Time-to-live for cache entries (0 = no expiration)
	MetricsEnabled bool          // Enable metrics collection
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Enabled:        true,
		MaxSize:        1000,
		TTL:            0, // No expiration by default
		MetricsEnabled: true,
	}
}

// CacheMetrics holds cache performance metrics
type CacheMetrics struct {
	Hits      uint64    // Cache hits
	Misses    uint64    // Cache misses
	Evictions uint64    // Number of evictions
	Size      int       // Current cache size
	HitRate   float64   // Hit rate percentage
	LastReset time.Time // Last metrics reset time
}

// FingerprintCache interface for caching ClientHello specs
type FingerprintCache interface {
	Get(key string) (*utls.ClientHelloSpec, bool)
	Set(key string, spec *utls.ClientHelloSpec)
	Clear()
	Metrics() CacheMetrics
	ResetMetrics()
	Size() int
}

// LRUCache implements FingerprintCache using LRU eviction
type LRUCache struct {
	cache          *lru.Cache[string, *cacheEntry]
	mu             sync.RWMutex
	config         *CacheConfig
	hits           atomic.Uint64
	misses         atomic.Uint64
	evictions      atomic.Uint64
	metricsResetAt time.Time
}

// cacheEntry wraps a ClientHelloSpec with metadata
type cacheEntry struct {
	spec      *utls.ClientHelloSpec
	createdAt time.Time
}

// NewLRUCache creates a new LRU cache for fingerprints
func NewLRUCache(config *CacheConfig) (*LRUCache, error) {
	if config == nil {
		config = DefaultCacheConfig()
	}

	if config.MaxSize <= 0 {
		config.MaxSize = 1000
	}

	cache, err := lru.NewWithEvict(config.MaxSize, func(key string, value *cacheEntry) {
		// Eviction callback - not used but available for future metrics
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	return &LRUCache{
		cache:          cache,
		config:         config,
		metricsResetAt: time.Now(),
	}, nil
}

// Get retrieves a ClientHelloSpec from cache
func (c *LRUCache) Get(key string) (*utls.ClientHelloSpec, bool) {
	if !c.config.Enabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache.Get(key)
	if !ok {
		if c.config.MetricsEnabled {
			c.misses.Add(1)
		}
		return nil, false
	}

	// Check TTL if configured
	if c.config.TTL > 0 && time.Since(entry.createdAt) > c.config.TTL {
		c.mu.RUnlock()
		c.mu.Lock()
		c.cache.Remove(key)
		c.mu.Unlock()
		c.mu.RLock()

		if c.config.MetricsEnabled {
			c.misses.Add(1)
			c.evictions.Add(1)
		}
		return nil, false
	}

	if c.config.MetricsEnabled {
		c.hits.Add(1)
	}

	return entry.spec, true
}

// Set stores a ClientHelloSpec in cache
func (c *LRUCache) Set(key string, spec *utls.ClientHelloSpec) {
	if !c.config.Enabled || spec == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &cacheEntry{
		spec:      spec,
		createdAt: time.Now(),
	}

	evicted := c.cache.Add(key, entry)
	if evicted && c.config.MetricsEnabled {
		c.evictions.Add(1)
	}
}

// Clear removes all entries from cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Purge()
}

// Metrics returns current cache metrics
func (c *LRUCache) Metrics() CacheMetrics {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses

	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100.0
	}

	return CacheMetrics{
		Hits:      hits,
		Misses:    misses,
		Evictions: c.evictions.Load(),
		Size:      c.Size(),
		HitRate:   hitRate,
		LastReset: c.metricsResetAt,
	}
}

// ResetMetrics resets all metrics counters
func (c *LRUCache) ResetMetrics() {
	c.hits.Store(0)
	c.misses.Store(0)
	c.evictions.Store(0)
	c.metricsResetAt = time.Now()
}

// Size returns current cache size
func (c *LRUCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache.Len()
}

// Global cache instance
var (
	globalCache     FingerprintCache
	globalCacheMu   sync.RWMutex
	globalCacheOnce sync.Once
)

// InitGlobalCache initializes the global fingerprint cache
func InitGlobalCache(config *CacheConfig) error {
	cache, err := NewLRUCache(config)
	if err != nil {
		return err
	}

	globalCacheMu.Lock()
	globalCache = cache
	globalCacheMu.Unlock()

	return nil
}

// GetGlobalCache returns the global cache instance, initializing if needed
func GetGlobalCache() FingerprintCache {
	globalCacheOnce.Do(func() {
		cache, _ := NewLRUCache(DefaultCacheConfig())
		globalCache = cache
	})

	globalCacheMu.RLock()
	defer globalCacheMu.RUnlock()
	return globalCache
}

// Cache key generation functions

// CacheKeyForFile generates a cache key for a JSON file based on path and modification time
func CacheKeyForFile(filePath string) (string, error) {
	stat, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("file:%s:%d", filePath, stat.ModTime().Unix())
	hash := sha256.Sum256([]byte(data))
	return "file:" + hex.EncodeToString(hash[:]), nil
}

// CacheKeyForJA3 generates a cache key for a JA3 fingerprint string
func CacheKeyForJA3(ja3 string) string {
	hash := sha256.Sum256([]byte(ja3))
	return "ja3:" + hex.EncodeToString(hash[:])
}

// CacheKeyForJA4 generates a cache key for a JA4 fingerprint string
func CacheKeyForJA4(ja4 string) string {
	hash := sha256.Sum256([]byte(ja4))
	return "ja4:" + hex.EncodeToString(hash[:])
}

// CacheKeyForProfile generates a cache key for a browser profile
func CacheKeyForProfile(profileName, serverName string) string {
	data := fmt.Sprintf("profile:%s:%s", profileName, serverName)
	hash := sha256.Sum256([]byte(data))
	return "profile:" + hex.EncodeToString(hash[:])
}
