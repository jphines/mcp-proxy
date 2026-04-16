package gateway

import "context"

// AuthStrategy defines how the proxy obtains a credential for a downstream server.
type AuthStrategy string

const (
	// AuthStrategyOAuth resolves a per-user OAuth access token from the enrollment store.
	AuthStrategyOAuth AuthStrategy = "oauth"
	// AuthStrategyXAA exchanges the caller's Okta ID-JAG token via RFC 8693 (future).
	AuthStrategyXAA AuthStrategy = "xaa"
	// AuthStrategyStatic resolves a long-lived API key from the vault at org scope.
	AuthStrategyStatic AuthStrategy = "static"
	// AuthStrategySTS assumes an AWS IAM role via STS AssumeRoleWithWebIdentity,
	// using the caller's validated JWT as the web identity token.
	// The resulting temporary credentials are injected into the downstream call.
	AuthStrategySTS AuthStrategy = "sts"
	// AuthStrategyNone means no credential is required for the downstream server.
	// The downstream call is made without any authentication header injection.
	AuthStrategyNone AuthStrategy = "none"
)

// CredentialResolver selects and resolves the appropriate credential strategy
// for a given downstream server and caller identity.
type CredentialResolver interface {
	// Resolve returns a credential ready for injection into the downstream call.
	// May return EnrollmentRequiredError when the server uses OAuth and the
	// identity has not yet completed the enrollment flow.
	Resolve(ctx context.Context, identity *Identity, server *ServerConfig) (*Credential, error)
}
