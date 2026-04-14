package oauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	xoauth2 "golang.org/x/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/mocks"
	"github.com/ro-eng/mcp-proxy/internal/oauth"
)

var testSecret = []byte("a-32-byte-hmac-secret-for-testing!")

func newEnrollment(t *testing.T, store gateway.CredentialStore, reg gateway.ServerRegistry) *oauth.Enrollment {
	t.Helper()
	return oauth.NewEnrollment(oauth.EnrollmentOptions{
		CredentialStore: store,
		ServerRegistry:  reg,
		TokenCache:      oauth.NewTokenCache(5 * time.Minute),
		HMACSecret:      testSecret,
		ProxyBaseURL:    "https://proxy.test.internal",
	})
}

func validToken(access string) *xoauth2.Token {
	return &xoauth2.Token{
		AccessToken: access,
		Expiry:      time.Now().Add(time.Hour),
	}
}

// --- state ---

func TestSignAndVerifyState(t *testing.T) {
	t.Parallel()
	state, err := oauth.SignState(testSecret, "user@test.com", "github", "verifier123")
	require.NoError(t, err)
	assert.NotEmpty(t, state)

	claims, err := oauth.VerifyState(testSecret, state)
	require.NoError(t, err)
	assert.Equal(t, "user@test.com", claims.Subject)
	assert.Equal(t, "github", claims.ServiceID)
	assert.Equal(t, "verifier123", claims.Verifier)
}

func TestVerifyState_InvalidMAC(t *testing.T) {
	t.Parallel()
	state, err := oauth.SignState(testSecret, "u", "svc", "v")
	require.NoError(t, err)

	// Tamper with the last character.
	tampered := state[:len(state)-1] + "X"
	_, err = oauth.VerifyState(testSecret, tampered)
	require.Error(t, err)
}

func TestVerifyState_WrongSecret(t *testing.T) {
	t.Parallel()
	state, err := oauth.SignState(testSecret, "u", "svc", "v")
	require.NoError(t, err)

	_, err = oauth.VerifyState([]byte("different-secret-of-32-bytes-here"), state)
	require.Error(t, err)
}

// --- token cache ---

func TestTokenCache_SetGet(t *testing.T) {
	t.Parallel()
	c := oauth.NewTokenCache(time.Minute)
	c.Set("alice", "github", validToken("access1"))

	got, ok := c.Get("alice", "github")
	require.True(t, ok)
	assert.Equal(t, "access1", got.AccessToken)
}

func TestTokenCache_MissOnUnknownKey(t *testing.T) {
	t.Parallel()
	c := oauth.NewTokenCache(time.Minute)
	_, ok := c.Get("alice", "nonexistent")
	assert.False(t, ok)
}

func TestTokenCache_MissOnExpiredToken(t *testing.T) {
	t.Parallel()
	c := oauth.NewTokenCache(time.Minute)

	tok := &xoauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Second),
	}
	c.Set("alice", "svc", tok)

	_, ok := c.Get("alice", "svc")
	assert.False(t, ok)
}

func TestTokenCache_Delete(t *testing.T) {
	t.Parallel()
	c := oauth.NewTokenCache(time.Minute)
	c.Set("bob", "jira", validToken("tok"))
	c.Delete("bob", "jira")
	_, ok := c.Get("bob", "jira")
	assert.False(t, ok)
}

// --- IsEnrolled ---

func TestEnrollment_IsEnrolled_CacheHit(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	reg := mocks.NewMockServerRegistry(t)

	enroll := newEnrollment(t, store, reg)
	enroll.TokenCache().Set("alice", "github", validToken("access"))

	ok, err := enroll.IsEnrolled(context.Background(), &gateway.Identity{Subject: "alice"}, "github")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestEnrollment_IsEnrolled_StoreHit(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	reg := mocks.NewMockServerRegistry(t)

	store.EXPECT().Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, "github").
		Return(&gateway.Credential{Type: gateway.CredTypeOAuthRefresh, Value: []byte("refresh")}, nil)

	enroll := newEnrollment(t, store, reg)
	ok, err := enroll.IsEnrolled(context.Background(), &gateway.Identity{Subject: "alice"}, "github")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestEnrollment_IsEnrolled_NotEnrolled(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	reg := mocks.NewMockServerRegistry(t)

	store.EXPECT().Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, "github").
		Return(nil, gateway.ErrCredentialNotFound)

	enroll := newEnrollment(t, store, reg)
	ok, err := enroll.IsEnrolled(context.Background(), &gateway.Identity{Subject: "alice"}, "github")
	require.NoError(t, err)
	assert.False(t, ok)
}

// --- AccessToken ---

func TestEnrollment_AccessToken_CacheHit(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	reg := mocks.NewMockServerRegistry(t)

	enroll := newEnrollment(t, store, reg)
	enroll.TokenCache().Set("alice", "github", validToken("my-access-token"))

	cred, err := enroll.AccessToken(context.Background(), &gateway.Identity{Subject: "alice"}, "github")
	require.NoError(t, err)
	assert.Equal(t, gateway.CredTypeOAuthAccess, cred.Type)
	assert.Equal(t, []byte("my-access-token"), cred.Value)
}

func TestEnrollment_AccessToken_NotEnrolledReturnsEnrollmentError(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	reg := mocks.NewMockServerRegistry(t)

	store.EXPECT().Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, "github").
		Return(nil, gateway.ErrCredentialNotFound)
	reg.EXPECT().Get(context.Background(), "github").
		Return(&gateway.ServerConfig{ID: "github", Name: "GitHub"}, nil)

	enroll := newEnrollment(t, store, reg)
	_, err := enroll.AccessToken(context.Background(), &gateway.Identity{Subject: "alice"}, "github")
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrEnrollmentRequired))
}

// --- Revoke ---

func TestEnrollment_Revoke_RemovesFromCacheAndStore(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	reg := mocks.NewMockServerRegistry(t)

	scope := gateway.CredentialScope{Level: gateway.ScopeSession, OwnerID: "alice", ServiceID: "github"}
	store.EXPECT().Revoke(context.Background(), scope).Return(nil)
	reg.EXPECT().Get(context.Background(), "github").
		Return(&gateway.ServerConfig{ID: "github", OAuthProvider: &gateway.OAuthProvider{}}, nil)

	enroll := newEnrollment(t, store, reg)
	enroll.TokenCache().Set("alice", "github", validToken("access"))

	require.NoError(t, enroll.Revoke(context.Background(), &gateway.Identity{Subject: "alice"}, "github"))

	_, ok := enroll.TokenCache().Get("alice", "github")
	assert.False(t, ok, "cache should be cleared after revoke")
}
