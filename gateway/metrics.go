package gateway

// MetricsCollector records Prometheus-compatible operational metrics.
// All methods are safe to call concurrently and must not block.
type MetricsCollector interface {
	// ToolCallTotal increments the tool call counter.
	// decision is the PolicyAction string ("allow", "deny", etc.).
	ToolCallTotal(serverID, toolName, decision string)

	// ToolCallDuration records the total proxy overhead in milliseconds.
	ToolCallDuration(serverID, toolName string, ms int64)

	// DownstreamDuration records the downstream server call latency in milliseconds.
	DownstreamDuration(serverID string, ms int64)

	// CredentialResolutionDuration records credential resolution latency in milliseconds.
	CredentialResolutionDuration(serverID, strategy string, ms int64)

	// ApprovalWaitDuration records how long a call waited for HITL approval.
	ApprovalWaitDuration(serverID string, ms int64)

	// CircuitBreakerState records the current state (0=closed, 1=open, 2=half-open).
	CircuitBreakerState(serverID string, state int)

	// ActiveSessions updates the gauge of currently active MCP sessions.
	ActiveSessions(delta int)

	// DownstreamError increments the downstream error counter.
	DownstreamError(serverID, toolName, errType string)

	// EnrollmentRequired increments the counter for calls blocked by missing enrollment.
	EnrollmentRequired(serverID string)

	// PolicyEvalError increments the counter for fail-open policy evaluation errors.
	PolicyEvalError(serverID, toolName string)
}
