package store

import (
	"context"
	"fmt"
	"time"
)

// ApprovalRecord is a persisted HITL approval workflow entry.
type ApprovalRecord struct {
	RequestID        string
	ToolNamespaced   string
	ArgumentsSummary string
	CallerSub        string
	CallerType       string
	PolicyRule       string
	PolicyReason     string
	Channel          string
	TimeoutSeconds   int
	Status           string // pending | approved | rejected | modified | timed_out
	Outcome          string
	ModifiedArgs     map[string]any
	ApproverSub      string
	CreatedAt        time.Time
	DecidedAt        *time.Time
}

// InsertApprovalRequest persists a new approval request in pending state.
func (db *DB) InsertApprovalRequest(ctx context.Context, r *ApprovalRecord) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO approval_requests (
			request_id, tool_namespaced, arguments_summary,
			caller_sub, caller_type, policy_rule, policy_reason,
			channel, timeout_seconds, status, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10)
	`,
		r.RequestID, r.ToolNamespaced, r.ArgumentsSummary,
		r.CallerSub, r.CallerType, r.PolicyRule, r.PolicyReason,
		r.Channel, r.TimeoutSeconds, r.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting approval request %s: %w", r.RequestID, err)
	}
	return nil
}

// UpdateApprovalOutcome records the human's decision on a pending request.
func (db *DB) UpdateApprovalOutcome(ctx context.Context, requestID, status, outcome, approverSub string, modifiedArgs map[string]any, decidedAt time.Time) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE approval_requests
		SET status        = $2,
		    outcome       = $3,
		    approver_sub  = $4,
		    modified_args = $5,
		    decided_at    = $6
		WHERE request_id = $1
	`, requestID, status, outcome, approverSub, modifiedArgs, decidedAt)
	if err != nil {
		return fmt.Errorf("updating approval outcome for %s: %w", requestID, err)
	}
	return nil
}

// GetApprovalRequest retrieves an approval request by ID.
func (db *DB) GetApprovalRequest(ctx context.Context, requestID string) (*ApprovalRecord, error) {
	row := db.pool.QueryRow(ctx, `
		SELECT request_id, tool_namespaced, arguments_summary,
		       caller_sub, caller_type, policy_rule, policy_reason,
		       channel, timeout_seconds, status,
		       COALESCE(outcome,''), COALESCE(approver_sub,''),
		       modified_args, created_at, decided_at
		FROM approval_requests WHERE request_id = $1
	`, requestID)

	var r ApprovalRecord
	err := row.Scan(
		&r.RequestID, &r.ToolNamespaced, &r.ArgumentsSummary,
		&r.CallerSub, &r.CallerType, &r.PolicyRule, &r.PolicyReason,
		&r.Channel, &r.TimeoutSeconds, &r.Status,
		&r.Outcome, &r.ApproverSub,
		&r.ModifiedArgs, &r.CreatedAt, &r.DecidedAt,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
