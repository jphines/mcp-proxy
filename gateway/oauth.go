package gateway

import "context"

// OAuthEnrollment manages the per-user OAuth enrollment lifecycle.
// Each engineer completes a one-time authorization flow per SaaS service;
// after enrollment, credentials are auto-refreshed transparently.
type OAuthEnrollment interface {
	// InitiateFlow generates a PKCE-protected authorization URL for the given
	// identity and service. The engineer opens this URL in a browser to grant consent.
	// Returns the full authorization URL including signed state parameter.
	InitiateFlow(ctx context.Context, identity *Identity, serviceID string) (authURL string, err error)

	// HandleCallback processes the OAuth callback after the engineer grants consent.
	// It validates the state signature, exchanges the code for tokens, and stores
	// the refresh token in the CredentialStore.
	HandleCallback(ctx context.Context, code, stateParam string) error

	// IsEnrolled reports whether the given identity has a valid enrollment for the service.
	// Checks the in-memory access token cache first, then the vault.
	IsEnrolled(ctx context.Context, identity *Identity, serviceID string) (bool, error)

	// AccessToken returns a valid access token for the given identity and service.
	// Checks the in-memory token cache first. If the cached token is expired or absent,
	// exchanges the stored refresh token for a new access token and updates the cache.
	// Returns EnrollmentRequiredError when the identity has no stored refresh token.
	AccessToken(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)

	// Revoke removes the stored enrollment for the given identity and service.
	// Calls the provider's revocation endpoint and deletes the credential from vault.
	Revoke(ctx context.Context, identity *Identity, serviceID string) error
}
