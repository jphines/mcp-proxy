package proxy

import (
	"context"
	"errors"
	"time"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// dispatchMiddleware is the terminal stage of the pipeline. It calls the
// downstream MCP server via the circuit breaker and records downstream latency.
// next is intentionally not called; dispatch has no successor.
func (p *Proxy) dispatchMiddleware(ctx context.Context, tc *gateway.ToolCallContext, _ gateway.MiddlewareFunc) {
	start := time.Now()

	execErr := p.deps.ServerRegistry.Execute(ctx, tc.ServerID, func() error {
		result, statusCode, err := p.callDownstream(ctx, tc)
		if err != nil {
			return err
		}
		tc.Response = result
		tc.StatusCode = statusCode
		return nil
	})

	tc.DownstreamMs = time.Since(start).Milliseconds()
	p.deps.MetricsCollector.DownstreamDuration(tc.ServerID, tc.DownstreamMs)

	if execErr != nil {
		tc.Err = execErr
		errType := "downstream_error"
		if errors.Is(execErr, gateway.ErrCircuitOpen) {
			errType = "circuit_open"
		}
		p.deps.MetricsCollector.DownstreamError(tc.ServerID, tc.ToolName, errType)
	}

	// Record the total call outcome regardless of success or failure.
	decision := gateway.ActionAllow
	if tc.Decision != nil {
		decision = tc.Decision.Action
	}
	p.deps.MetricsCollector.ToolCallTotal(tc.ServerID, tc.ToolName, string(decision))
}
