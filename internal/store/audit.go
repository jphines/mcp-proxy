package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditRow is the database representation of a single audit event.
type AuditRow struct {
	EventID          string
	InstanceID       string
	Timestamp        time.Time
	RequestID        string
	CallerSub        string
	CallerType       string
	CallerGroups     []string
	CallerSessionID  string
	ToolNamespaced   string
	ArgumentsHash    string
	CredentialRef    string
	Decision         string
	PolicyRule       string
	PolicyReason     string
	PolicyEvalError  string
	Workspace        string
	DownstreamStatus int
	LatencyMs        int64
	DownstreamMs     int64
	RedactionsApplied int
	PrevHash         string
	Hash             string
}

// InsertAuditEvent appends an audit event row.
func (db *DB) InsertAuditEvent(ctx context.Context, r *AuditRow) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO audit_events (
			event_id, instance_id, timestamp, request_id,
			caller_sub, caller_type, caller_groups, caller_session_id,
			tool_namespaced, arguments_hash, credential_ref,
			decision, policy_rule, policy_reason, policy_eval_error,
			workspace, downstream_status, latency_ms, downstream_ms,
			redactions_applied, prev_hash, hash
		) VALUES (
			$1,$2,$3,$4, $5,$6,$7,$8, $9,$10,$11,
			$12,$13,$14,$15, $16,$17,$18,$19, $20,$21,$22
		)
	`,
		r.EventID, r.InstanceID, r.Timestamp, r.RequestID,
		r.CallerSub, r.CallerType, r.CallerGroups, r.CallerSessionID,
		r.ToolNamespaced, r.ArgumentsHash, r.CredentialRef,
		r.Decision, r.PolicyRule, r.PolicyReason, r.PolicyEvalError,
		r.Workspace, r.DownstreamStatus, r.LatencyMs, r.DownstreamMs,
		r.RedactionsApplied, r.PrevHash, r.Hash,
	)
	if err != nil {
		return fmt.Errorf("inserting audit event %s: %w", r.EventID, err)
	}
	return nil
}

// LastAuditEvent returns the most recent audit event for the given instance,
// used to continue the hash chain after a restart. Returns pgx.ErrNoRows when
// no events exist yet (genesis case).
func (db *DB) LastAuditEvent(ctx context.Context, instanceID string) (*AuditRow, error) {
	row := db.pool.QueryRow(ctx, `
		SELECT event_id, prev_hash, hash
		FROM audit_events
		WHERE instance_id = $1
		ORDER BY timestamp DESC
		LIMIT 1
	`, instanceID)

	var r AuditRow
	r.InstanceID = instanceID
	if err := row.Scan(&r.EventID, &r.PrevHash, &r.Hash); err != nil {
		return nil, err
	}
	return &r, nil
}

// VerifyChain walks every audit event for the given instance in ascending
// timestamp order and recomputes each hash to detect tampering.
// Returns an error identifying the first broken link.
func (db *DB) VerifyChain(ctx context.Context, instanceID string, hashFn func(row *AuditRow, prevHash string) string) error {
	rows, err := db.pool.Query(ctx, `
		SELECT event_id, instance_id, timestamp, request_id,
		       caller_sub, caller_type, caller_groups, caller_session_id,
		       tool_namespaced, arguments_hash, credential_ref,
		       decision, policy_rule, policy_reason, policy_eval_error,
		       workspace, downstream_status, latency_ms, downstream_ms,
		       redactions_applied, prev_hash, hash
		FROM audit_events
		WHERE instance_id = $1
		ORDER BY timestamp ASC
	`, instanceID)
	if err != nil {
		return fmt.Errorf("querying audit chain: %w", err)
	}
	defer rows.Close()

	var prev string
	count := 0

	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(
			&r.EventID, &r.InstanceID, &r.Timestamp, &r.RequestID,
			&r.CallerSub, &r.CallerType, &r.CallerGroups, &r.CallerSessionID,
			&r.ToolNamespaced, &r.ArgumentsHash, &r.CredentialRef,
			&r.Decision, &r.PolicyRule, &r.PolicyReason, &r.PolicyEvalError,
			&r.Workspace, &r.DownstreamStatus, &r.LatencyMs, &r.DownstreamMs,
			&r.RedactionsApplied, &r.PrevHash, &r.Hash,
		); err != nil {
			return fmt.Errorf("scanning audit row: %w", err)
		}

		if count == 0 {
			prev = r.PrevHash // genesis: trust the stored prev_hash for first event
		} else if r.PrevHash != prev {
			return fmt.Errorf("hash chain broken at event %s: expected prev_hash %q, got %q",
				r.EventID, prev, r.PrevHash)
		}

		expected := hashFn(&r, r.PrevHash)
		if r.Hash != expected {
			return fmt.Errorf("hash mismatch at event %s: expected %q, got %q",
				r.EventID, expected, r.Hash)
		}

		prev = r.Hash
		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating audit rows: %w", err)
	}
	return nil
}

// UpsertChainGenesis stores (or retrieves) the per-instance genesis seed.
func (db *DB) UpsertChainGenesis(ctx context.Context, instanceID, seed string) (string, error) {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO audit_chain_genesis (instance_id, seed)
		VALUES ($1, $2)
		ON CONFLICT (instance_id) DO NOTHING
	`, instanceID, seed)
	if err != nil {
		return "", fmt.Errorf("upserting chain genesis for %s: %w", instanceID, err)
	}

	// Read back the canonical seed (may differ from input if another instance
	// already seeded it before us).
	row := db.pool.QueryRow(ctx, `
		SELECT seed FROM audit_chain_genesis WHERE instance_id = $1
	`, instanceID)

	var stored string
	if err := row.Scan(&stored); err != nil {
		if err == pgx.ErrNoRows {
			return seed, nil
		}
		return "", fmt.Errorf("reading chain genesis for %s: %w", instanceID, err)
	}
	return stored, nil
}
