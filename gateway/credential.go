package gateway

import (
	"context"
	"time"
)

// ScopeLevel identifies which tier of the credential hierarchy to use.
type ScopeLevel string

const (
	// ScopeSession is a credential scoped to a single authenticated session.
	ScopeSession ScopeLevel = "session"
	// ScopeAgent is a credential scoped to a registered agent identity.
	ScopeAgent ScopeLevel = "agent"
	// ScopeOrg is a shared organisational credential (e.g., a shared API key).
	ScopeOrg ScopeLevel = "org"
)

// CredentialType classifies the secret material.
type CredentialType string

const (
	// CredTypeAPIKey is a long-lived API key.
	CredTypeAPIKey CredentialType = "api_key"
	// CredTypeOAuthAccess is a short-lived OAuth access token.
	CredTypeOAuthAccess CredentialType = "oauth_access_token"
	// CredTypeOAuthRefresh is a long-lived OAuth refresh token stored in vault.
	CredTypeOAuthRefresh CredentialType = "oauth_refresh_token"
	// CredTypeIAMRole is an AWS IAM role ARN to be assumed via STS.
	CredTypeIAMRole CredentialType = "iam_role"
	// CredTypeBearerToken is a generic bearer token.
	CredTypeBearerToken CredentialType = "bearer_token"
	// CredTypeBasicAuth is a username:password pair (base64-encoded value).
	CredTypeBasicAuth CredentialType = "basic_auth"
)

// CredentialScope identifies the owner and service for a stored credential.
type CredentialScope struct {
	// Level is the hierarchy tier.
	Level ScopeLevel
	// OwnerID is the subject that owns this credential (empty for org-scope).
	OwnerID string
	// ServiceID matches the downstream server registration ID.
	ServiceID string
}

// Credential holds resolved secret material ready for injection.
// Secret material is in Value; all other fields are metadata.
type Credential struct {
	// Type classifies the secret for injection logic.
	Type CredentialType
	// Value is the raw secret bytes. Must be zeroed via Zero() after use.
	Value []byte
	// ExpiresAt is the expiry time; nil means no known expiry.
	ExpiresAt *time.Time
	// Metadata carries auxiliary data (e.g., role ARN, token endpoint).
	Metadata map[string]string
}

// Zero wipes secret material from memory.
// Must be called via defer in every middleware that holds a resolved Credential.
func (c *Credential) Zero() {
	for i := range c.Value {
		c.Value[i] = 0
	}
	c.Value = nil
}

// CredentialStore is an abstract secret backend.
// AWS Secrets Manager is the initial implementation; the interface enables
// swapping to HashiCorp Vault or 1Password without changing the proxy core.
type CredentialStore interface {
	// Resolve returns the best available credential for the given identity and service.
	// Walks session → agent → org scope in order. When identity is nil, only org-scope
	// is checked (used for resolving the proxy's own OAuth client secrets).
	// Returns ErrCredentialNotFound when no credential exists at any scope.
	Resolve(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)

	// Store persists a credential at the given scope.
	Store(ctx context.Context, scope CredentialScope, cred *Credential) error

	// Revoke deletes a stored credential.
	Revoke(ctx context.Context, scope CredentialScope) error

	// Rotate refreshes a stored OAuth refresh token and returns the new access token.
	Rotate(ctx context.Context, scope CredentialScope) (*Credential, error)

	// List enumerates the credential scopes visible to the given identity.
	List(ctx context.Context, identity *Identity) ([]CredentialScope, error)
}
