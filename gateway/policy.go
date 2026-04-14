package gateway

import (
	"context"
	"time"
)

// PolicyAction is the outcome of policy evaluation for a tool call.
type PolicyAction string

const (
	// ActionAllow permits the tool call to proceed.
	ActionAllow PolicyAction = "allow"
	// ActionDeny blocks the tool call immediately.
	ActionDeny PolicyAction = "deny"
	// ActionRequireApproval gates the call on a human-in-the-loop decision.
	ActionRequireApproval PolicyAction = "require_approval"
	// ActionLog permits the call but records the matching rule for audit.
	ActionLog PolicyAction = "log"
)

// AuditLevel controls how much detail is captured in the audit record.
type AuditLevel string

const (
	// AuditMinimal records only identity, tool name, and decision.
	AuditMinimal AuditLevel = "minimal"
	// AuditStandard records the above plus arguments hash and latency.
	AuditStandard AuditLevel = "standard"
	// AuditFull records everything including full arguments (hashed for PHI tools).
	AuditFull AuditLevel = "full"
)

// ApprovalSpec describes the HITL approval parameters when action is require_approval.
type ApprovalSpec struct {
	// Channel is the delivery channel for the approval request (e.g., "slack").
	Channel string
	// Timeout is the maximum time to wait for a human decision before auto-rejecting.
	Timeout time.Duration
	// RequireDiff indicates the approver must supply a modified argument set.
	RequireDiff bool
}

// PolicyDecision is the result of evaluating policy rules against a tool call.
type PolicyDecision struct {
	// Action is the enforcement outcome.
	Action PolicyAction
	// Reason is a human-readable explanation for the decision.
	Reason string
	// Rule is the ID of the matching rule.
	Rule string
	// AuditLevel specifies how to record this call in the audit trail.
	AuditLevel AuditLevel
	// ApprovalSpec is set when Action is ActionRequireApproval.
	ApprovalSpec *ApprovalSpec
	// MatchedLogRules accumulates the IDs of log-action rules that matched.
	MatchedLogRules []string
}

// ToolCall carries the context of the tool invocation for policy evaluation.
type ToolCall struct {
	// ServerID is the registered downstream server identifier.
	ServerID string
	// ToolName is the bare tool name (without server prefix).
	ToolName string
	// Arguments are the tool call arguments.
	Arguments map[string]any
	// Tier is the severity/autonomy tier (1=observe, 5=red line).
	Tier int
	// Tags are metadata labels from the server registration.
	Tags map[string]string
}

// PolicyEngine evaluates tool calls against pre-authored declarative rules.
// Failures are fail-open: evaluation errors allow the call through with an audit warning.
type PolicyEngine interface {
	// Evaluate assesses a tool call against all loaded policy rules.
	// Returns a decision even when an error occurs (fail-open); callers should
	// log the error as an audit warning and proceed with the returned decision.
	Evaluate(ctx context.Context, identity *Identity, call *ToolCall) (*PolicyDecision, error)
	// Reload re-reads the policy configuration from disk.
	// On failure, the existing compiled rule set is retained unchanged.
	Reload(ctx context.Context) error
}
