package proxy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// approvalMiddleware blocks tool calls that require human-in-the-loop approval.
// If the policy decision is ActionRequireApproval it sends a Slack notification
// and waits for the human decision. Rejected / timed-out calls short-circuit.
// Modified arguments from the approver replace tc.Arguments before continuing.
func (p *Proxy) approvalMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	if tc.Decision == nil || tc.Decision.Action != gateway.ActionRequireApproval {
		next(ctx, tc)
		return
	}

	req := &gateway.ApprovalRequest{
		RequestID:        tc.RequestID,
		ToolNamespaced:   tc.ServerID + "::" + tc.ToolName,
		ArgumentsSummary: approvalArgumentsSummary(tc.Arguments),
		PolicyRule:       tc.Decision.Rule,
		PolicyReason:     tc.Decision.Reason,
		CreatedAt:        time.Now().UTC(),
	}
	if tc.Identity != nil {
		req.CallerSubject = tc.Identity.Subject
		req.CallerType = tc.Identity.Type
	}
	if tc.Decision.ApprovalSpec != nil {
		req.Spec = *tc.Decision.ApprovalSpec
	}

	start := time.Now()
	decision, err := p.deps.ApprovalService.Request(ctx, req)
	p.deps.MetricsCollector.ApprovalWaitDuration(tc.ServerID, time.Since(start).Milliseconds())

	if err != nil {
		tc.Err = fmt.Errorf("approval: %w", err)
		return
	}

	switch decision.Outcome {
	case gateway.ApprovalRejected:
		tc.Err = gateway.ErrApprovalRejected
		return
	case gateway.ApprovalTimedOut:
		tc.Err = gateway.ErrApprovalTimedOut
		return
	case gateway.ApprovalModified:
		if decision.ModifiedArguments != nil {
			tc.Arguments = decision.ModifiedArguments
		}
	}

	next(ctx, tc)
}

// approvalArgumentsSummary produces a PHI-safe summary of the tool arguments:
// field names and their Go type only, never the actual values.
func approvalArgumentsSummary(args map[string]any) string {
	if len(args) == 0 {
		return "(no arguments)"
	}
	parts := make([]string, 0, len(args))
	for k, v := range args {
		parts = append(parts, fmt.Sprintf("%s=%T", k, v))
	}
	return strings.Join(parts, ", ")
}
