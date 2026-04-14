package registry

import (
	"sync"
	"time"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// toolCache is an in-memory, per-server tool list cache with a configurable TTL.
type toolCache struct {
	mu      sync.RWMutex
	entries map[string]*toolCacheEntry
	ttl     time.Duration
}

type toolCacheEntry struct {
	tools     []gateway.Tool
	expiresAt time.Time
}

func newToolCache(ttl time.Duration) *toolCache {
	return &toolCache{
		entries: make(map[string]*toolCacheEntry),
		ttl:     ttl,
	}
}

// get returns the cached tools for serverID if present and not expired.
func (c *toolCache) get(serverID string) ([]gateway.Tool, bool) {
	c.mu.RLock()
	e, ok := c.entries[serverID]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.tools, true
}

// set stores tools for serverID with the configured TTL.
func (c *toolCache) set(serverID string, tools []gateway.Tool) {
	c.mu.Lock()
	c.entries[serverID] = &toolCacheEntry{
		tools:     tools,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// invalidate removes a server's cached tool list (called on hot-reload).
func (c *toolCache) invalidate(serverID string) {
	c.mu.Lock()
	delete(c.entries, serverID)
	c.mu.Unlock()
}
