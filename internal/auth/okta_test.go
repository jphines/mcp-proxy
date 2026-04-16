package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/auth"
)

const testAudience = "api://mcp-proxy-test"

// testKeys holds an RSA key pair and a JWKS HTTP server for unit tests.
type testKeys struct {
	privateKey *rsa.PrivateKey
	keyID      string
	server     *httptest.Server
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"

	// Build a JWKS containing the public key.
	pubKey, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.RS256))

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(pubKey))

	jwksBytes, err := json.Marshal(keySet)
	require.NoError(t, err)

	// Serve the JWKS from an in-process HTTP server.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testKeys{
		privateKey: priv,
		keyID:      kid,
		server:     srv,
	}
}

// buildToken creates a signed JWT for testing.
func (k *testKeys) buildToken(t *testing.T, opts ...func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()

	b := jwt.NewBuilder().
		Issuer(k.server.URL).
		Audience([]string{testAudience}).
		Subject("test-user@ro.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))

	for _, opt := range opts {
		b = opt(b)
	}

	tok, err := b.Build()
	require.NoError(t, err)

	privKey, err := jwk.FromRaw(k.privateKey)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, k.keyID))
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.RS256))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)
	return string(signed)
}

func newAuthenticatorFromTestKeys(t *testing.T, tk *testKeys) *auth.OktaAuthenticator {
	t.Helper()
	a := auth.NewOktaAuthenticator(tk.server.URL, testAudience)
	return a
}

// --- Tests ---

func TestAuthenticate_ValidToken(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t,
		func(b *jwt.Builder) *jwt.Builder {
			return b.
				Claim("groups", []string{"engineering", "platform-engineering"}).
				Claim("scp", "mcp:read mcp:write").
				Claim("sid", "session-abc-123").
				Claim("x-identity-type", "human")
		},
	)

	identity, err := a.Authenticate(context.Background(), token)
	require.NoError(t, err)

	assert.Equal(t, "test-user@ro.com", identity.Subject)
	assert.Equal(t, gateway.IdentityHuman, identity.Type)
	assert.Equal(t, []string{"engineering", "platform-engineering"}, identity.Groups)
	assert.Equal(t, []string{"mcp:read", "mcp:write"}, identity.Scopes)
	assert.Equal(t, "session-abc-123", identity.SessionID)
	assert.False(t, identity.TokenExpiry.IsZero())
}

func TestAuthenticate_EmptyToken(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	_, err := a.Authenticate(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrUnauthenticated))
}

func TestAuthenticate_ExpiredToken(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.
			IssuedAt(time.Now().Add(-2 * time.Hour)).
			Expiration(time.Now().Add(-time.Hour))
	})

	_, err := a.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrUnauthenticated), "expected ErrUnauthenticated, got: %v", err)
}

func TestAuthenticate_WrongIssuer(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Issuer("https://wrong-issuer.example.com")
	})

	_, err := a.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrUnauthenticated))
}

func TestAuthenticate_WrongAudience(t *testing.T) {
	tk := newTestKeys(t)
	a := auth.NewOktaAuthenticator(tk.server.URL, "api://different-audience")

	token := tk.buildToken(t) // uses testAudience

	_, err := a.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrUnauthenticated))
}

func TestAuthenticate_TamperedToken(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t)
	// Tamper with the payload section.
	tampered := token[:len(token)-10] + "AAAAAAAAAA"

	_, err := a.Authenticate(context.Background(), tampered)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrUnauthenticated))
}

func TestAuthenticate_AgentIdentityType(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.
			Subject("agent-rx-checker").
			Claim("x-identity-type", "agent").
			Claim("delegated_by", "jane@ro.com")
	})

	identity, err := a.Authenticate(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, gateway.IdentityAgent, identity.Type)
	assert.Equal(t, "jane@ro.com", identity.DelegatedBy)
}

func TestAuthenticate_ServiceIdentityViaAMR(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.
			Subject("svc-reporting").
			Claim("amr", []any{"swk"}) // software key → service identity
	})

	identity, err := a.Authenticate(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, gateway.IdentityService, identity.Type)
}

func TestAuthenticate_NoGroupsOrScopes(t *testing.T) {
	tk := newTestKeys(t)
	a := newAuthenticatorFromTestKeys(t, tk)

	token := tk.buildToken(t) // no groups, no scopes

	identity, err := a.Authenticate(context.Background(), token)
	require.NoError(t, err)
	assert.Empty(t, identity.Groups)
	assert.Empty(t, identity.Scopes)
}

func TestAuthenticate_JWKSServerUnavailable(t *testing.T) {
	// Point to a non-existent JWKS endpoint.
	a := auth.NewOktaAuthenticator("http://127.0.0.1:1", testAudience)

	// Any non-empty token value triggers a JWKS fetch.
	_, err := a.Authenticate(context.Background(), "any.token.value")
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrUnauthenticated))
}
