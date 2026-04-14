package gateway

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolCallContext is the mutable state threaded through the middleware pipeline
// for a single tool call. It is created per-request and must not be shared.
//
// Pipeline order (outermost first):
//
//	audit → auth → route → policy → approval → enrollment → credential → dispatch
type ToolCallContext struct {
	// RawRequest is the inbound MCP tool call request.
	RawRequest *mcp.CallToolParamsRaw

	// ServerID is the parsed server identifier from the namespaced tool name.
	// Set by routeMiddleware.
	ServerID string
	// ToolName is the bare tool name (without server prefix).
	// Set by routeMiddleware.
	ToolName string
	// Arguments are the decoded tool call arguments.
	// Set by routeMiddleware.
	Arguments map[string]any

	// ServerConfig is the resolved downstream server registration.
	// Set by routeMiddleware.
	ServerConfig *ServerConfig

	// Identity is the validated caller identity.
	// Set by authMiddleware.
	Identity *Identity

	// Decision is the policy evaluation outcome.
	// Set by policyMiddleware.
	Decision *PolicyDecision

	// Credential is the resolved and decrypted downstream credential.
	// Set by credentialMiddleware. Must be zeroed via defer cred.Zero() after dispatch.
	Credential *Credential
	// Injection describes how to attach the credential to the downstream request.
	// Set by credentialMiddleware.
	Injection *AuthInjection

	// Response is the result returned from the downstream server.
	// Set by dispatchMiddleware.
	Response *mcp.CallToolResult

	// StatusCode is the HTTP status from the downstream server (0 if not dispatched).
	StatusCode int
	// LatencyMs is the total proxy overhead including all middleware.
	// Set by auditMiddleware after the inner chain completes.
	LatencyMs int64
	// DownstreamMs is the downstream call latency only.
	// Set by dispatchMiddleware.
	DownstreamMs int64

	// Err holds the first error that caused the pipeline to short-circuit.
	// auditMiddleware reads this to determine the audit outcome.
	Err error

	// PolicyEvalErr holds a non-fatal policy evaluation error (fail-open path).
	PolicyEvalErr error

	// RequestID is an opaque correlation ID for the HTTP request.
	RequestID string

	// RedactionsApplied is the count of secret-detection redactions applied.
	RedactionsApplied int
}

// Middleware is a function that wraps the next step in the pipeline.
// It receives the call context, performs its work, and calls next to continue.
// Short-circuiting is achieved by not calling next.
type Middleware func(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc)

// MiddlewareFunc is the continuation function passed to each middleware.
type MiddlewareFunc func(ctx context.Context, tc *ToolCallContext)

// BuildPipeline composes middlewares into a single MiddlewareFunc.
// The first middleware in the slice is the outermost (executed first).
func BuildPipeline(middlewares ...Middleware) MiddlewareFunc {
	if len(middlewares) == 0 {
		return func(_ context.Context, _ *ToolCallContext) {}
	}
	return func(ctx context.Context, tc *ToolCallContext) {
		middlewares[0](ctx, tc, BuildPipeline(middlewares[1:]...))
	}
}
