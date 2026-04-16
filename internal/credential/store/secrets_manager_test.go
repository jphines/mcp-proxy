package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	credstore "github.com/jphines/mcp-proxy/internal/credential/store"
)

func TestEncryptedCache_SetAndGet(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t, 5*time.Second)

	key := credstore.ExportCacheKey("session", "user1", "github")
	plaintext := []byte("super-secret-token-value")

	require.NoError(t, cache.Set(key, plaintext))

	got, ok := cache.Get(key)
	require.True(t, ok)
	assert.Equal(t, plaintext, got)

	// Verify the stored plaintext is zeroed after retrieval (independent copy).
	got[0] = 'X'
	got2, ok2 := cache.Get(key)
	require.True(t, ok2)
	assert.Equal(t, plaintext, got2, "second get should return original value, not modified copy")
}

func TestEncryptedCache_MissOnUnknownKey(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t, 5*time.Second)

	_, ok := cache.Get("nonexistent-key")
	assert.False(t, ok)
}

func TestEncryptedCache_ScopeIsolation(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t, 5*time.Second)

	sessionKey := credstore.ExportCacheKey("session", "user1", "github")
	orgKey := credstore.ExportCacheKey("org", "", "github")

	require.NoError(t, cache.Set(sessionKey, []byte("session-token")))
	require.NoError(t, cache.Set(orgKey, []byte("org-token")))

	sessionVal, ok := cache.Get(sessionKey)
	require.True(t, ok)
	assert.Equal(t, []byte("session-token"), sessionVal)

	orgVal, ok2 := cache.Get(orgKey)
	require.True(t, ok2)
	assert.Equal(t, []byte("org-token"), orgVal)

	// Session key must not return org value.
	assert.NotEqual(t, sessionVal, orgVal)
}

func TestEncryptedCache_ExpiredEntryNotReturned(t *testing.T) {
	t.Parallel()
	// 10ms TTL — immediately expired for testing.
	cache := newTestCache(t, 10*time.Millisecond)

	key := credstore.ExportCacheKey("session", "user1", "svc")
	require.NoError(t, cache.Set(key, []byte("value")))

	time.Sleep(20 * time.Millisecond)

	_, ok := cache.Get(key)
	assert.False(t, ok, "expired entry should not be returned")
}

func TestEncryptedCache_DeleteRemovesEntry(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t, 5*time.Second)

	key := credstore.ExportCacheKey("org", "", "jira")
	require.NoError(t, cache.Set(key, []byte("token")))

	cache.Delete(key)
	_, ok := cache.Get(key)
	assert.False(t, ok)
}

func TestCacheKey_DifferentScopesProduceDifferentKeys(t *testing.T) {
	k1 := credstore.ExportCacheKey("session", "user1", "github")
	k2 := credstore.ExportCacheKey("org", "", "github")
	k3 := credstore.ExportCacheKey("session", "user2", "github")
	assert.NotEqual(t, k1, k2)
	assert.NotEqual(t, k1, k3)
	assert.NotEqual(t, k2, k3)
}

// --- helpers ---

func newTestCache(t *testing.T, ttl time.Duration) *credstore.ExportedCache {
	t.Helper()
	c, err := credstore.NewExportedCache(ttl)
	require.NoError(t, err)
	return c
}
