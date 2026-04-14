package oauth

import (
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type tokenKey struct {
	Subject   string
	ServiceID string
}

// TokenCache is an in-memory cache of live OAuth tokens indexed by (subject, serviceID).
// It is safe for concurrent use.
type TokenCache struct {
	mu     sync.Mutex
	tokens map[tokenKey]*oauth2.Token
}

// NewTokenCache creates an empty TokenCache and starts a background GC goroutine
// that evicts expired tokens every gcInterval.
func NewTokenCache(gcInterval time.Duration) *TokenCache {
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}
	go c.gc(gcInterval)
	return c
}

// Set stores tok for (subject, serviceID), replacing any existing entry.
func (c *TokenCache) Set(subject, serviceID string, tok *oauth2.Token) {
	c.mu.Lock()
	c.tokens[tokenKey{subject, serviceID}] = tok
	c.mu.Unlock()
}

// Get returns the token for (subject, serviceID) if it exists and is not expired.
// A token is considered valid if its expiry is more than 30 seconds in the future
// (matches oauth2 library convention).
func (c *TokenCache) Get(subject, serviceID string) (*oauth2.Token, bool) {
	c.mu.Lock()
	tok, ok := c.tokens[tokenKey{subject, serviceID}]
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	if !tok.Valid() {
		return nil, false
	}
	return tok, true
}

// Delete removes the cached token for (subject, serviceID).
func (c *TokenCache) Delete(subject, serviceID string) {
	c.mu.Lock()
	delete(c.tokens, tokenKey{subject, serviceID})
	c.mu.Unlock()
}

// gc periodically removes expired tokens.
func (c *TokenCache) gc(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		for k, tok := range c.tokens {
			if !tok.Valid() {
				delete(c.tokens, k)
			}
		}
		c.mu.Unlock()
	}
}
