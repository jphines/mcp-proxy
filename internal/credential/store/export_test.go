package store

import "time"

// This file exports internal types and functions for use by the _test package.
// It is compiled only during test builds.

// ExportedCache wraps encryptedCache with exported methods for white-box testing.
type ExportedCache struct {
	c *encryptedCache
}

// NewExportedCache creates a test-accessible cache.
func NewExportedCache(ttl time.Duration) (*ExportedCache, error) {
	c, err := newEncryptedCache(ttl)
	if err != nil {
		return nil, err
	}
	return &ExportedCache{c: c}, nil
}

// Set stores a value.
func (e *ExportedCache) Set(key string, value []byte) error { return e.c.set(key, value) }

// Get retrieves a value.
func (e *ExportedCache) Get(key string) ([]byte, bool) { return e.c.get(key) }

// Delete removes a value.
func (e *ExportedCache) Delete(key string) { e.c.delete(key) }

// ExportCacheKey exposes the cacheKey function for testing scope isolation.
func ExportCacheKey(scopeLevel, ownerID, serviceID string) string {
	return cacheKey(scopeLevel, ownerID, serviceID)
}
