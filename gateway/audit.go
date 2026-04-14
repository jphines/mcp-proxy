package gateway

import (
	"context"
	"time"
)

// AuditEvent is a structured record of a single tool call and its outcome.
// It forms part of a tamper-evident SHA-256 hash chain.
type AuditEvent struct {
	// EventID is a ULID uniquely identifying this event.
	EventID string
	// Timestamp is when the event was recorded (UTC).
	Timestamp time.Time
	// RequestID is an opaque correlation identifier for the HTTP request.
	RequestID string

	// CallerSubject is the identity.Subject of the caller.
	CallerSubject string
	// CallerType is the identity.Type of the caller.
	CallerType IdentityType
	// CallerGroups lists the caller's group memberships.
	CallerGroups []string
	// CallerSessionID is the session context from the caller's token.
	CallerSessionID string

	// ToolNamespaced is the full "serverID::toolName" identifier.
	ToolNamespaced string
	// ArgumentsHash is the SHA-256 hex digest of the JSON-encoded arguments.
	// Raw argument values are never stored; hashing prevents PHI leakage.
	ArgumentsHash string

	// CredentialRef is the vault path or scope used to resolve the credential.
	// Credential values are never stored.
	CredentialRef string

	// Decision is the policy action that was applied.
	Decision PolicyAction
	// PolicyRule is the ID of the rule that determined the decision.
	PolicyRule string
	// PolicyReason is the human-readable reason from the matching rule.
	PolicyReason string

	// Workspace is the deployment workspace (e.g., "production", "staging").
	Workspace string

	// DownstreamStatus is the HTTP status code from the downstream server, or 0 if
	// the call was blocked before dispatch.
	DownstreamStatus int
	// LatencyMs is the total proxy overhead in milliseconds.
	LatencyMs int64
	// DownstreamMs is the downstream call latency in milliseconds.
	DownstreamMs int64

	// RedactionsApplied is the count of secret-detection redactions applied.
	RedactionsApplied int

	// PolicyEvalError is set when policy evaluation produced a non-fatal error
	// and the call was allowed through with a fail-open decision.
	PolicyEvalError string

	// PrevHash is the SHA-256 hex digest of the previous event in the chain.
	// The first event in an instance's chain uses "genesis".
	PrevHash string
	// Hash is the SHA-256 hex digest of this event (computed over all fields except Hash).
	Hash string
}

// AuditLogger persists tamper-evident audit events.
// The AuditMiddleware always calls Emit, even for denied calls.
type AuditLogger interface {
	// Emit records an audit event and appends it to the hash chain.
	// Implementations must not block the calling goroutine for more than a few milliseconds;
	// batching and async flushing are expected.
	Emit(ctx context.Context, event *AuditEvent) error

	// VerifyChain walks the audit records for the given instance and recomputes
	// each hash to detect tampering. Returns an error identifying the first broken link.
	VerifyChain(ctx context.Context, instanceID string) error
}
