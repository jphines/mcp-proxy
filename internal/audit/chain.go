// Package audit implements gateway.AuditLogger backed by AWS CloudWatch Logs with an
// optional PostgreSQL tamper-evident hash chain.
//
// Hash chain algorithm:
//
//	event_json = canonical JSON of AuditEvent with Hash="" and PrevHash=<prevHash>
//	event.Hash = hex(SHA-256(event_json))
//
// Canonical JSON: keys sorted alphabetically, no extra whitespace.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/store"
)

// ComputeHash fills event.PrevHash and computes event.Hash in place.
// event.Hash must be "" when passed in (so it is excluded from the input).
func ComputeHash(event *gateway.AuditEvent, prevHash string) {
	event.PrevHash = prevHash
	event.Hash = "" // excluded from hash input

	data, err := canonicalJSON(event)
	if err != nil {
		// Fallback: hash the error message itself so the chain is never empty.
		sum := sha256.Sum256([]byte(fmt.Sprintf("ERROR:%s:%s", event.EventID, err)))
		event.Hash = hex.EncodeToString(sum[:])
		return
	}

	sum := sha256.Sum256(data)
	event.Hash = hex.EncodeToString(sum[:])
}

// RowHash implements the hashFn signature expected by store.DB.VerifyChain.
// It converts a store.AuditRow back to a gateway.AuditEvent for hashing so that
// the same algorithm is used for both write-path and verification.
func RowHash(row *store.AuditRow, prevHash string) string {
	event := rowToEvent(row)
	ComputeHash(event, prevHash)
	return event.Hash
}

// canonicalJSON marshals v with keys sorted deterministically.
// encoding/json already sorts map keys, and struct field order is fixed,
// so standard json.Marshal is canonical for our struct.
func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// rowToEvent converts a store.AuditRow into a gateway.AuditEvent for hashing.
// Only the fields that are included in the hash computation are populated.
func rowToEvent(r *store.AuditRow) *gateway.AuditEvent {
	return &gateway.AuditEvent{
		EventID:           r.EventID,
		Timestamp:         r.Timestamp,
		RequestID:         r.RequestID,
		CallerSubject:     r.CallerSub,
		CallerType:        gateway.IdentityType(r.CallerType),
		CallerGroups:      r.CallerGroups,
		CallerSessionID:   r.CallerSessionID,
		ToolNamespaced:    r.ToolNamespaced,
		ArgumentsHash:     r.ArgumentsHash,
		CredentialRef:     r.CredentialRef,
		Decision:          gateway.PolicyAction(r.Decision),
		PolicyRule:        r.PolicyRule,
		PolicyReason:      r.PolicyReason,
		Workspace:         r.Workspace,
		DownstreamStatus:  r.DownstreamStatus,
		LatencyMs:         r.LatencyMs,
		DownstreamMs:      r.DownstreamMs,
		RedactionsApplied: r.RedactionsApplied,
		PolicyEvalError:   r.PolicyEvalError,
	}
}
