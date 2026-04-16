package proxy

import (
	"context"
	"log/slog"

	"github.com/jphines/mcp-proxy/gateway"
)

// policyMiddleware evaluates the loaded CEL policy rules against the inbound
// tool call. Deny short-circuits. RequireApproval and Log are recorded in tc.Decision
// and execution continues to the approval/log middleware further down the pipeline.
// Evaluation errors are fail-open: the call proceeds and the error is noted in
// tc.PolicyEvalErr for audit.
func (p *Proxy) policyMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	call := &gateway.ToolCall{
		ServerID:  tc.ServerID,
		ToolName:  tc.ToolName,
		Arguments: tc.Arguments,
		Tier:      tc.ServerConfig.DataTier,
		Tags:      tc.ServerConfig.Tags,
	}

	slog.DebugContext(ctx, "policy: evaluating",
		slog.String("server_id", call.ServerID),
		slog.String("tool_name", call.ToolName),
		slog.String("identity_type", string(tc.Identity.Type)),
	)

	decision, evalErr := p.deps.PolicyEngine.Evaluate(ctx, tc.Identity, call)
	if evalErr != nil {
		// Fail-open: record the error but allow the call through.
		tc.PolicyEvalErr = evalErr
		slog.WarnContext(ctx, "policy: evaluation error (fail-open)",
			slog.String("server_id", tc.ServerID),
			slog.String("tool_name", tc.ToolName),
			slog.String("error", evalErr.Error()),
		)
		p.deps.MetricsCollector.PolicyEvalError(tc.ServerID, tc.ToolName)
	}

	tc.Decision = decision

	if decision != nil {
		slog.DebugContext(ctx, "policy: decision",
			slog.String("action", string(decision.Action)),
			slog.String("rule", decision.Rule),
		)
	}

	if decision != nil && decision.Action == gateway.ActionDeny {
		tc.Err = gateway.ErrPolicyDenied
		p.deps.MetricsCollector.ToolCallTotal(tc.ServerID, tc.ToolName, string(gateway.ActionDeny))
		return
	}

	next(ctx, tc)
}
