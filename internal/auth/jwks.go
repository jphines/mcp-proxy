// Package auth implements Okta JWT validation for the MCP proxy.
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	jwksCacheTTL      = time.Hour
	jwksRefreshBuffer = 5 * time.Minute
	jwksRetryDelay    = 5 * time.Second
)

// jwksCache fetches and caches the JWKS for a given issuer.
// Keys are refreshed in the background before the TTL expires.
type jwksCache struct {
	mu          sync.RWMutex
	set         jwk.Set
	fetchedAt   time.Time
	issuer      string
	jwksURL     string
	fetchFunc   func(ctx context.Context, url string) (jwk.Set, error)
}

func newJWKSCache(issuer string) *jwksCache {
	return &jwksCache{
		issuer:  issuer,
		jwksURL: issuer + "/.well-known/jwks.json",
		fetchFunc: func(ctx context.Context, url string) (jwk.Set, error) {
			return jwk.Fetch(ctx, url)
		},
	}
}

// Get returns the current key set, fetching it if the cache is empty or expired.
func (c *jwksCache) Get(ctx context.Context) (jwk.Set, error) {
	c.mu.RLock()
	if c.set != nil && time.Since(c.fetchedAt) < jwksCacheTTL-jwksRefreshBuffer {
		set := c.set
		c.mu.RUnlock()
		return set, nil
	}
	c.mu.RUnlock()

	return c.refresh(ctx)
}

// refresh unconditionally fetches a fresh key set.
func (c *jwksCache) refresh(ctx context.Context) (jwk.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: another goroutine may have refreshed while we waited for the lock.
	if c.set != nil && time.Since(c.fetchedAt) < jwksCacheTTL-jwksRefreshBuffer {
		return c.set, nil
	}

	set, err := c.fetchFunc(ctx, c.jwksURL)
	if err != nil {
		// If we have a stale set, return it with a warning rather than failing.
		if c.set != nil {
			slog.WarnContext(ctx, "JWKS refresh failed; using stale key set",
				slog.String("issuer", c.issuer),
				slog.Any("error", err),
			)
			return c.set, nil
		}
		return nil, fmt.Errorf("fetching JWKS from %s: %w", c.jwksURL, err)
	}

	c.set = set
	c.fetchedAt = time.Now()
	return set, nil
}

// StartBackgroundRefresh launches a goroutine that proactively refreshes the
// cache before the TTL expires. The goroutine exits when ctx is cancelled.
func (c *jwksCache) StartBackgroundRefresh(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(jwksCacheTTL - jwksRefreshBuffer)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := c.refresh(ctx); err != nil {
					slog.WarnContext(ctx, "background JWKS refresh failed",
						slog.String("issuer", c.issuer),
						slog.Any("error", err),
					)
				}
			}
		}
	}()
}
