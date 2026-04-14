package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// OktaAuthenticator validates Okta-issued JWTs and returns canonical Identity objects.
// It does not issue tokens; it only validates them.
type OktaAuthenticator struct {
	issuer   string
	audience string
	cache    *jwksCache
}

// NewOktaAuthenticator constructs an authenticator for the given Okta issuer and audience.
// It does not fetch the JWKS immediately; that happens on the first Authenticate call.
func NewOktaAuthenticator(issuer, audience string) *OktaAuthenticator {
	return &OktaAuthenticator{
		issuer:   issuer,
		audience: audience,
		cache:    newJWKSCache(issuer),
	}
}

// StartBackgroundRefresh begins proactive JWKS cache refresh.
// Should be called once during proxy startup.
func (a *OktaAuthenticator) StartBackgroundRefresh(ctx context.Context) {
	a.cache.StartBackgroundRefresh(ctx)
}

// Authenticate validates the bearer token and returns the caller's identity.
// Returns gateway.ErrUnauthenticated on any validation failure.
func (a *OktaAuthenticator) Authenticate(ctx context.Context, token string) (*gateway.Identity, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: no token provided", gateway.ErrUnauthenticated)
	}

	keys, err := a.cache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", gateway.ErrUnauthenticated, err)
	}

	parsed, err := jwt.Parse([]byte(token),
		jwt.WithKeySet(keys),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		jwt.WithValidate(true),
	)
	if err != nil {
		// Unknown kid: JWKS may have rotated — refresh once and retry.
		if isUnknownKIDError(err) {
			keys, refreshErr := a.cache.refresh(ctx)
			if refreshErr != nil {
				return nil, fmt.Errorf("%w: JWKS refresh after unknown kid failed: %s", gateway.ErrUnauthenticated, refreshErr)
			}
			parsed, err = jwt.Parse([]byte(token),
				jwt.WithKeySet(keys),
				jwt.WithIssuer(a.issuer),
				jwt.WithAudience(a.audience),
				jwt.WithValidate(true),
			)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s", gateway.ErrUnauthenticated, err)
		}
	}

	claims, err := parsed.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: extracting claims: %s", gateway.ErrUnauthenticated, err)
	}

	identity := &gateway.Identity{
		Subject:     parsed.Subject(),
		Type:        detectIdentityType(claims),
		Groups:      extractGroups(claims),
		Scopes:      extractScopes(claims),
		TokenExpiry: parsed.Expiration(),
		Claims:      claims,
	}

	if sid, ok := claims[claimSessionID].(string); ok {
		identity.SessionID = sid
	}
	if delegated, ok := claims[claimDelegatedBy].(string); ok {
		identity.DelegatedBy = delegated
	}

	return identity, nil
}

// isUnknownKIDError detects whether the JWT parse error was caused by an
// unrecognised key ID, which triggers a JWKS refresh-and-retry.
func isUnknownKIDError(err error) bool {
	if err == nil {
		return false
	}
	// lestrrat-go/jwx returns a specific error type for key not found.
	// We check the error message as the library doesn't export a sentinel.
	msg := err.Error()
	return contains(msg, "failed to find key") ||
		contains(msg, "kid not found") ||
		contains(msg, "could not find matching key")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// ensure OktaAuthenticator implements gateway.Authenticator.
var _ gateway.Authenticator = (*OktaAuthenticator)(nil)

// unwrapErr is a helper for error chain inspection in tests.
func unwrapErr(err error) error {
	return errors.Unwrap(err)
}

var _ = unwrapErr // suppress unused warning during incremental build
