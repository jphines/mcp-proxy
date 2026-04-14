package gateway

import (
	"context"
	"time"
)

// ApprovalOutcome is the result of a human-in-the-loop decision.
type ApprovalOutcome string

const (
	// ApprovalApproved means the human approved the call with the original arguments.
	ApprovalApproved ApprovalOutcome = "approved"
	// ApprovalRejected means the human rejected the call.
	ApprovalRejected ApprovalOutcome = "rejected"
	// ApprovalModified means the human approved but supplied altered arguments.
	ApprovalModified ApprovalOutcome = "modified"
	// ApprovalTimedOut means no decision arrived before the timeout; auto-rejected.
	ApprovalTimedOut ApprovalOutcome = "timed_out"
)

// ApprovalRequest carries the information presented to the human approver.
type ApprovalRequest struct {
	// RequestID is a unique identifier for this approval workflow.
	RequestID string
	// ToolNamespaced is the full "serverID::toolName" being requested.
	ToolNamespaced string
	// ArgumentsSummary is a safe, human-readable summary of the arguments
	// (PHI-safe: no raw values, only field names and value shapes).
	ArgumentsSummary string
	// CallerSubject identifies who is requesting the action.
	CallerSubject string
	// CallerType is the identity type of the caller.
	CallerType IdentityType
	// PolicyRule is the rule ID that triggered the approval requirement.
	PolicyRule string
	// PolicyReason is the human-readable reason for the approval requirement.
	PolicyReason string
	// Spec carries channel and timeout configuration.
	Spec ApprovalSpec
	// CreatedAt is when the approval request was created.
	CreatedAt time.Time
}

// ApprovalDecision is the outcome returned by an approver.
type ApprovalDecision struct {
	// RequestID matches the corresponding ApprovalRequest.
	RequestID string
	// Outcome is the human's decision.
	Outcome ApprovalOutcome
	// ModifiedArguments is set when Outcome is ApprovalModified.
	ModifiedArguments map[string]any
	// ApproverSubject identifies the human who made the decision.
	ApproverSubject string
	// DecidedAt is when the decision was made.
	DecidedAt time.Time
}

// ApprovalService manages human-in-the-loop approval workflows.
type ApprovalService interface {
	// Request sends an approval request and blocks until a decision arrives or
	// the context is cancelled. Timeout is enforced via the Spec in the request.
	// Returns ApprovalTimedOut when no decision arrives within the timeout.
	Request(ctx context.Context, req *ApprovalRequest) (*ApprovalDecision, error)

	// Decide delivers an approval decision for a pending request.
	// Called by the Slack webhook callback handler.
	// Returns an error if the requestID is not found or has already been decided.
	Decide(ctx context.Context, decision *ApprovalDecision) error
}
