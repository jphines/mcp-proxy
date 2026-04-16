// Package metrics implements gateway.MetricsCollector backed by Prometheus.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/jphines/mcp-proxy/gateway"
)

type prometheusCollector struct {
	toolCallsTotal      *prometheus.CounterVec
	toolCallDuration    *prometheus.HistogramVec
	downstreamDuration  *prometheus.HistogramVec
	credResolution      *prometheus.HistogramVec
	approvalWait        *prometheus.HistogramVec
	circuitBreakerState *prometheus.GaugeVec
	activeSessions      prometheus.Gauge
	downstreamErrors    *prometheus.CounterVec
	enrollmentRequired  *prometheus.CounterVec
	policyEvalErrors    *prometheus.CounterVec
}

// New returns a MetricsCollector registered on the default Prometheus registerer.
// Call once at startup; subsequent calls register duplicate metrics and will panic.
func New() gateway.MetricsCollector {
	return &prometheusCollector{
		toolCallsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mcp_proxy",
			Name:      "tool_calls_total",
			Help:      "Total tool calls partitioned by server, tool name, and policy decision.",
		}, []string{"server_id", "tool_name", "decision"}),

		toolCallDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mcp_proxy",
			Name:      "tool_call_duration_ms",
			Help:      "End-to-end proxy overhead in milliseconds (excludes downstream latency).",
			Buckets:   []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500},
		}, []string{"server_id", "tool_name"}),

		downstreamDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mcp_proxy",
			Name:      "downstream_duration_ms",
			Help:      "Downstream MCP server call latency in milliseconds.",
			Buckets:   []float64{5, 10, 25, 50, 100, 250, 500, 1000, 5000},
		}, []string{"server_id"}),

		credResolution: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mcp_proxy",
			Name:      "credential_resolution_duration_ms",
			Help:      "Credential resolution latency in milliseconds.",
			Buckets:   []float64{1, 5, 10, 25, 50, 100, 250},
		}, []string{"server_id", "strategy"}),

		approvalWait: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mcp_proxy",
			Name:      "approval_wait_duration_ms",
			Help:      "HITL approval wait latency in milliseconds.",
			Buckets:   []float64{1000, 5000, 15000, 30000, 60000, 120000, 300000},
		}, []string{"server_id"}),

		circuitBreakerState: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "mcp_proxy",
			Name:      "circuit_breaker_state",
			Help:      "Current circuit breaker state per server: 0=closed, 1=open, 2=half-open.",
		}, []string{"server_id"}),

		activeSessions: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "mcp_proxy",
			Name:      "active_sessions",
			Help:      "Number of currently active MCP sessions.",
		}),

		downstreamErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mcp_proxy",
			Name:      "downstream_errors_total",
			Help:      "Total downstream call errors partitioned by server, tool, and error type.",
		}, []string{"server_id", "tool_name", "err_type"}),

		enrollmentRequired: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mcp_proxy",
			Name:      "enrollment_required_total",
			Help:      "Total tool calls blocked because OAuth enrollment is missing.",
		}, []string{"server_id"}),

		policyEvalErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mcp_proxy",
			Name:      "policy_eval_errors_total",
			Help:      "Total fail-open policy evaluation errors.",
		}, []string{"server_id", "tool_name"}),
	}
}

func (p *prometheusCollector) ToolCallTotal(serverID, toolName, decision string) {
	p.toolCallsTotal.WithLabelValues(serverID, toolName, decision).Inc()
}

func (p *prometheusCollector) ToolCallDuration(serverID, toolName string, ms int64) {
	p.toolCallDuration.WithLabelValues(serverID, toolName).Observe(float64(ms))
}

func (p *prometheusCollector) DownstreamDuration(serverID string, ms int64) {
	p.downstreamDuration.WithLabelValues(serverID).Observe(float64(ms))
}

func (p *prometheusCollector) CredentialResolutionDuration(serverID, strategy string, ms int64) {
	p.credResolution.WithLabelValues(serverID, strategy).Observe(float64(ms))
}

func (p *prometheusCollector) ApprovalWaitDuration(serverID string, ms int64) {
	p.approvalWait.WithLabelValues(serverID).Observe(float64(ms))
}

func (p *prometheusCollector) CircuitBreakerState(serverID string, state int) {
	p.circuitBreakerState.WithLabelValues(serverID).Set(float64(state))
}

func (p *prometheusCollector) ActiveSessions(delta int) {
	p.activeSessions.Add(float64(delta))
}

func (p *prometheusCollector) DownstreamError(serverID, toolName, errType string) {
	p.downstreamErrors.WithLabelValues(serverID, toolName, errType).Inc()
}

func (p *prometheusCollector) EnrollmentRequired(serverID string) {
	p.enrollmentRequired.WithLabelValues(serverID).Inc()
}

func (p *prometheusCollector) PolicyEvalError(serverID, toolName string) {
	p.policyEvalErrors.WithLabelValues(serverID, toolName).Inc()
}

var _ gateway.MetricsCollector = (*prometheusCollector)(nil)
