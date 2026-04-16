package oauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func validToken(expiresIn time.Duration) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: "access-token-value",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(expiresIn),
	}
}

func TestTokenCache_SetAndGet(t *testing.T) {
	t.Parallel()
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}

	tok := validToken(time.Hour)
	c.Set("alice", "google", tok)

	got, ok := c.Get("alice", "google")
	require.True(t, ok)
	assert.Equal(t, "access-token-value", got.AccessToken)
}

func TestTokenCache_GetMiss(t *testing.T) {
	t.Parallel()
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}

	_, ok := c.Get("nobody", "google")
	assert.False(t, ok)
}

func TestTokenCache_ExpiredTokenNotReturned(t *testing.T) {
	t.Parallel()
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}

	// Expired token — oauth2.Token.Valid() checks Expiry > now + expiryDelta (10s).
	tok := &oauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Minute),
	}
	c.Set("alice", "google", tok)

	_, ok := c.Get("alice", "google")
	assert.False(t, ok, "expired token should not be returned")
}

func TestTokenCache_Delete(t *testing.T) {
	t.Parallel()
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}

	c.Set("alice", "google", validToken(time.Hour))
	c.Delete("alice", "google")

	_, ok := c.Get("alice", "google")
	assert.False(t, ok, "deleted token should not be returned")
}

func TestTokenCache_ScopeIsolation(t *testing.T) {
	t.Parallel()
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}

	c.Set("alice", "google", &oauth2.Token{AccessToken: "google-tok", Expiry: time.Now().Add(time.Hour)})
	c.Set("alice", "github", &oauth2.Token{AccessToken: "github-tok", Expiry: time.Now().Add(time.Hour)})
	c.Set("bob", "google", &oauth2.Token{AccessToken: "bob-tok", Expiry: time.Now().Add(time.Hour)})

	g1, ok := c.Get("alice", "google")
	require.True(t, ok)
	assert.Equal(t, "google-tok", g1.AccessToken)

	g2, ok := c.Get("alice", "github")
	require.True(t, ok)
	assert.Equal(t, "github-tok", g2.AccessToken)

	g3, ok := c.Get("bob", "google")
	require.True(t, ok)
	assert.Equal(t, "bob-tok", g3.AccessToken)
}

func TestTokenCache_OverwriteExisting(t *testing.T) {
	t.Parallel()
	c := &TokenCache{tokens: make(map[tokenKey]*oauth2.Token)}

	c.Set("alice", "google", &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(time.Hour)})
	c.Set("alice", "google", &oauth2.Token{AccessToken: "new", Expiry: time.Now().Add(time.Hour)})

	got, ok := c.Get("alice", "google")
	require.True(t, ok)
	assert.Equal(t, "new", got.AccessToken)
}

func TestTokenCache_GC_EvictsExpiredTokens(t *testing.T) {
	t.Parallel()

	// Use a very short GC interval so we can observe eviction quickly.
	c := NewTokenCache(50 * time.Millisecond)

	// Store a token that's already expired. oauth2.Token.Valid() returns false
	// when Expiry < now + expiryDelta (10s), so this token is immediately invalid.
	tok := &oauth2.Token{
		AccessToken: "already-expired",
		Expiry:      time.Now().Add(-time.Minute),
	}
	c.Set("alice", "google", tok)

	// Confirm it's in the map but Get returns false (expired).
	c.mu.Lock()
	_, exists := c.tokens[tokenKey{"alice", "google"}]
	c.mu.Unlock()
	assert.True(t, exists, "token should be in map before GC runs")

	_, ok := c.Get("alice", "google")
	assert.False(t, ok, "expired token should not be returned by Get")

	// Wait for GC to run and evict the expired entry from the map.
	time.Sleep(150 * time.Millisecond)

	c.mu.Lock()
	_, exists = c.tokens[tokenKey{"alice", "google"}]
	c.mu.Unlock()
	assert.False(t, exists, "GC should have evicted the expired token from the map")
}
