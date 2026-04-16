// Package auth implements JWT validation for the MCP proxy.
package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/jphines/mcp-proxy/gateway"
)

// OktaAuthenticator validates JWTs from any OIDC-compatible provider
// (Auth0, Okta, demo-jwt, …) and returns canonical Identity objects.
//
// The name is kept for API compatibility; the implementation now uses
// go-oidc and works with any RFC-compliant OIDC provider.
type OktaAuthenticator struct {
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
}

// AuthOption configures an OktaAuthenticator.
type AuthOption func(*OktaAuthenticator)

// WithGroupsClaim overrides the JWT claim key used to extract group membership.
// Use this for providers that store groups in a namespace claim, e.g. an Auth0
// Post-Login Action that injects "https://mcp-proxy/groups".
func WithGroupsClaim(claim string) AuthOption {
	return func(a *OktaAuthenticator) { a.groupsClaim = claim }
}

// NewOktaAuthenticator constructs an authenticator for the given OIDC issuer
// and audience. JWKS are fetched lazily on the first Authenticate call;
// go-oidc's RemoteKeySet handles caching and automatic key rotation.
//
// No network I/O happens at construction time — startup cannot be blocked
// by a temporarily unavailable IdP.
//
// issuer examples:
//   - Auth0:    "https://your-tenant.us.auth0.com/"
//   - Okta:     "https://your-tenant.okta.com/oauth2/default"
//   - demo-jwt: "http://demo-jwt:9999"
//
// audience is the expected JWT aud claim value (e.g. "https://api/mcp-proxy").
func NewOktaAuthenticator(issuer, audience string, opts ...AuthOption) *OktaAuthenticator {
	// Derive the JWKS URL from the issuer using the OIDC well-known convention.
	// Auth0:    https://tenant/.well-known/jwks.json  ✓
	// demo-jwt: http://demo-jwt:9999/.well-known/jwks.json  ✓
	jwksURL := strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"

	// NewRemoteKeySet creates a lazy JWKS fetcher backed by go-oidc's cache.
	// context.Background() is fine here — the key set lives for the process lifetime.
	keySet := oidc.NewRemoteKeySet(context.Background(), jwksURL)

	a := &OktaAuthenticator{
		verifier: oidc.NewVerifier(issuer, keySet, &oidc.Config{
			ClientID: audience, // audience check: token aud must contain this value
		}),
		groupsClaim: claimGroups, // default "groups"; override with WithGroupsClaim
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// StartBackgroundRefresh is a no-op kept for API compatibility.
// go-oidc's RemoteKeySet handles JWKS caching and rotation automatically —
// on an unknown key ID it re-fetches immediately, no polling needed.
func (a *OktaAuthenticator) StartBackgroundRefresh(_ context.Context) {}

// Authenticate validates the bearer token and returns the caller's identity.
// Returns gateway.ErrUnauthenticated on any validation failure.
func (a *OktaAuthenticator) Authenticate(ctx context.Context, token string) (*gateway.Identity, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: no token provided", gateway.ErrUnauthenticated)
	}

	// Verify signature, issuer, audience, and expiry in one call.
	// On an unknown key ID, go-oidc automatically re-fetches the JWKS once.
	idToken, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", gateway.ErrUnauthenticated, err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: extracting claims: %s", gateway.ErrUnauthenticated, err)
	}

	identity := &gateway.Identity{
		Subject:     idToken.Subject,
		Type:        detectIdentityType(claims),
		Groups:      extractGroups(claims, a.groupsClaim),
		Scopes:      extractScopes(claims),
		TokenExpiry: idToken.Expiry,
		Claims:      claims,
		RawToken:    token,
	}

	if sid, ok := claims[claimSessionID].(string); ok {
		identity.SessionID = sid
	}
	if delegated, ok := claims[claimDelegatedBy].(string); ok {
		identity.DelegatedBy = delegated
	}

	return identity, nil
}

// ensure OktaAuthenticator implements gateway.Authenticator.
var _ gateway.Authenticator = (*OktaAuthenticator)(nil)
