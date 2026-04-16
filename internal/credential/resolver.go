// Package credential provides the CompositeResolver, which routes credential
// resolution to the appropriate strategy based on a server's AuthStrategy setting.
package credential

import (
	"context"
	"fmt"

	"github.com/jphines/mcp-proxy/gateway"
)

// CompositeResolver implements gateway.CredentialResolver by routing to the
// appropriate sub-strategy based on the server's AuthStrategy.
type CompositeResolver struct {
	store      gateway.CredentialStore
	enrollment gateway.OAuthEnrollment
	sts        *STSResolver
}

// NewCompositeResolver creates a resolver with OAuth, static, STS, and XAA strategies.
// stsResolver may be nil if STS is not configured.
func NewCompositeResolver(
	store gateway.CredentialStore,
	enrollment gateway.OAuthEnrollment,
	stsResolver *STSResolver,
) *CompositeResolver {
	return &CompositeResolver{
		store:      store,
		enrollment: enrollment,
		sts:        stsResolver,
	}
}

// Resolve returns a credential for the given identity and server configuration.
// Strategy routing:
//
//	oauth  → check enrollment → return current access token (or EnrollmentRequiredError)
//	static → org-scope credential store lookup
//	xaa    → ErrXAANotSupported (Phase 1 stub)
//	none   → empty credential (no injection)
func (r *CompositeResolver) Resolve(ctx context.Context, identity *gateway.Identity, server *gateway.ServerConfig) (*gateway.Credential, error) {
	switch server.Strategy {
	case gateway.AuthStrategyOAuth:
		return r.resolveOAuth(ctx, identity, server)
	case gateway.AuthStrategyStatic:
		return r.resolveStatic(ctx, server)
	case gateway.AuthStrategySTS:
		return r.resolveSTS(ctx, identity, server)
	case gateway.AuthStrategyXAA:
		return nil, gateway.ErrXAANotSupported
	case gateway.AuthStrategyNone:
		return &gateway.Credential{}, nil
	default:
		return nil, fmt.Errorf("credential: unknown auth strategy %q for server %s", server.Strategy, server.ID)
	}
}

// resolveOAuth returns an access token for the enrolled identity.
// Returns EnrollmentRequiredError when the identity has not completed the OAuth flow.
func (r *CompositeResolver) resolveOAuth(ctx context.Context, identity *gateway.Identity, server *gateway.ServerConfig) (*gateway.Credential, error) {
	cred, err := r.enrollment.AccessToken(ctx, identity, server.ID)
	if err != nil {
		return nil, err // may be EnrollmentRequiredError or a transient error
	}
	return cred, nil
}

// resolveSTS exchanges the caller's JWT for temporary AWS credentials via AssumeRoleWithWebIdentity.
func (r *CompositeResolver) resolveSTS(ctx context.Context, identity *gateway.Identity, server *gateway.ServerConfig) (*gateway.Credential, error) {
	if r.sts == nil {
		return nil, fmt.Errorf("credential: STS strategy requested for server %s but no STS client configured", server.ID)
	}
	return r.sts.Resolve(ctx, identity, server)
}

// resolveStatic fetches a long-lived API key from the credential store at org scope.
func (r *CompositeResolver) resolveStatic(ctx context.Context, server *gateway.ServerConfig) (*gateway.Credential, error) {
	cred, err := r.store.Resolve(ctx, nil, server.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("credential: resolving static credential for %s: %w", server.ID, err)
	}
	return cred, nil
}

var _ gateway.CredentialResolver = (*CompositeResolver)(nil)
