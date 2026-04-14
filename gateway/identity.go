// Package gateway defines the core interfaces and domain types for the MCP proxy.
// All implementations live in internal/; this package contains only contracts.
package gateway

import (
	"context"
	"time"
)

// IdentityType classifies who is making a tool call.
type IdentityType string

const (
	// IdentityHuman represents a human engineer authenticated via Okta.
	IdentityHuman IdentityType = "human"
	// IdentityAgent represents a registered AI agent with declared capabilities.
	IdentityAgent IdentityType = "agent"
	// IdentityService represents a non-interactive service account.
	IdentityService IdentityType = "service"
)

// Identity is the canonical caller representation populated by the Authenticator.
// Every field comes from validated Okta claims — nothing is caller-supplied.
type Identity struct {
	// Subject is the unique Okta subject identifier (sub claim).
	Subject string
	// Type classifies the caller as human, agent, or service.
	Type IdentityType
	// Groups lists the caller's Okta group memberships.
	Groups []string
	// Scopes lists the authorized OAuth scopes from the token.
	Scopes []string
	// SessionID is an opaque session context from the token.
	SessionID string
	// DelegatedBy holds the subject of the principal that delegated to this caller.
	// Empty for non-delegated calls.
	DelegatedBy string
	// Claims holds raw Okta JWT claims for CEL policy evaluation.
	Claims map[string]any
	// TokenExpiry is when the validated token expires.
	TokenExpiry time.Time
	// RawToken is the original validated bearer token string.
	// Retained for STS AssumeRoleWithWebIdentity calls.
	RawToken string
}

// Authenticator validates inbound tokens and returns a canonical Identity.
// It does not issue tokens; validation only.
type Authenticator interface {
	// Authenticate validates the bearer token and returns the caller's identity.
	// Returns ErrUnauthenticated on any validation failure.
	Authenticate(ctx context.Context, token string) (*Identity, error)
}
