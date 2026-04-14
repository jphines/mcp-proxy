// Package credential provides the CompositeResolver, which routes credential
// resolution to the appropriate strategy based on a server's AuthStrategy setting.
package credential

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// stsClient is a minimal interface over the STS SDK client.
type stsClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// CompositeResolver implements gateway.CredentialResolver by routing to the
// appropriate sub-strategy based on the server's AuthStrategy.
type CompositeResolver struct {
	store      gateway.CredentialStore
	enrollment gateway.OAuthEnrollment
	stsClient  stsClient
}

// NewCompositeResolver creates a resolver with all strategies available.
// stsClient may be nil when STS strategy servers are not configured.
func NewCompositeResolver(
	store gateway.CredentialStore,
	enrollment gateway.OAuthEnrollment,
	stsClient stsClient,
) *CompositeResolver {
	return &CompositeResolver{
		store:      store,
		enrollment: enrollment,
		stsClient:  stsClient,
	}
}

// Resolve returns a credential for the given identity and server configuration.
// Strategy routing:
//
//	oauth  → check enrollment → return current access token (or EnrollmentRequiredError)
//	static → org-scope credential store lookup
//	sts    → AssumeRoleWithWebIdentity using the caller's JWT
//	xaa    → ErrXAANotSupported (Phase 1 stub)
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

// resolveStatic fetches a long-lived API key from the credential store at org scope.
func (r *CompositeResolver) resolveStatic(ctx context.Context, server *gateway.ServerConfig) (*gateway.Credential, error) {
	cred, err := r.store.Resolve(ctx, nil, server.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("credential: resolving static credential for %s: %w", server.ID, err)
	}
	return cred, nil
}

// resolveSTS calls AssumeRoleWithWebIdentity using the caller's JWT and returns
// temporary AWS credentials (access key ID, secret, session token) as a JSON-encoded
// value. The dispatch middleware injects these as AWS environment variables.
func (r *CompositeResolver) resolveSTS(ctx context.Context, identity *gateway.Identity, server *gateway.ServerConfig) (*gateway.Credential, error) {
	if r.stsClient == nil {
		return nil, fmt.Errorf("credential: STS client not configured for server %s", server.ID)
	}
	if identity == nil {
		return nil, fmt.Errorf("credential: STS strategy requires an authenticated identity")
	}

	roleARN := server.CredentialRef
	sessionName := "mcp-proxy-" + identity.Subject
	if len(sessionName) > 64 {
		sessionName = sessionName[:64]
	}

	out, err := r.stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(identity.RawToken),
	})
	if err != nil {
		return nil, fmt.Errorf("credential: AssumeRoleWithWebIdentity for %s: %w", server.ID, err)
	}

	creds := out.Credentials
	if creds == nil {
		return nil, fmt.Errorf("credential: STS returned nil credentials for %s", server.ID)
	}

	// Encode the three STS fields as metadata so dispatch can inject them.
	var expiresAt *time.Time
	if creds.Expiration != nil {
		t := *creds.Expiration
		expiresAt = &t
	}

	return &gateway.Credential{
		Type:  gateway.CredTypeIAMRole,
		Value: []byte(aws.ToString(creds.SessionToken)),
		ExpiresAt: expiresAt,
		Metadata: map[string]string{
			"access_key_id":     aws.ToString(creds.AccessKeyId),
			"secret_access_key": aws.ToString(creds.SecretAccessKey),
			"session_token":     aws.ToString(creds.SessionToken),
		},
	}, nil
}

var _ gateway.CredentialResolver = (*CompositeResolver)(nil)
