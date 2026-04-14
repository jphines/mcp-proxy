package gateway

import "context"

// TokenExchanger performs RFC 8693 token exchange to derive downstream credentials
// from a caller's Okta session without stored refresh tokens (XAA/ID-JAG flow).
//
// This interface is included for future compatibility with Okta's XAA federation
// feature. It is not yet active in Phase 1; implementations return ErrXAANotSupported.
type TokenExchanger interface {
	// Exchange derives a downstream credential from the caller's identity token.
	// The returned Credential is ready for injection and must be zeroed after use.
	Exchange(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)
}
