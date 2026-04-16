package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/mocks"
)

// --- helpers ---

func boolPtr(b bool) *bool { return &b }

// noopMetrics returns a MetricsCollector mock that accepts any call without assertions.
func noopMetrics(t *testing.T) *mocks.MockMetricsCollector {
	t.Helper()
	m := mocks.NewMockMetricsCollector(t)
	m.On("ToolCallTotal", mock.Anything, mock.Anything, mock.Anything).Maybe()
	m.On("ToolCallDuration", mock.Anything, mock.Anything, mock.Anything).Maybe()
	m.On("DownstreamDuration", mock.Anything, mock.Anything).Maybe()
	m.On("CredentialResolutionDuration", mock.Anything, mock.Anything, mock.Anything).Maybe()
	m.On("ApprovalWaitDuration", mock.Anything, mock.Anything).Maybe()
	m.On("CircuitBreakerState", mock.Anything, mock.Anything).Maybe()
	m.On("ActiveSessions", mock.Anything).Maybe()
	m.On("DownstreamError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	m.On("EnrollmentRequired", mock.Anything).Maybe()
	m.On("PolicyEvalError", mock.Anything, mock.Anything).Maybe()
	return m
}

// makeRawRequest builds a *mcp.CallToolParamsRaw for "serverID__toolName".
func makeRawRequest(serverID, toolName string, args map[string]any) *mcp.CallToolParamsRaw {
	var rawArgs json.RawMessage
	if args != nil {
		rawArgs, _ = json.Marshal(args)
	}
	return &mcp.CallToolParamsRaw{
		Name:      toMCPName(serverID + "::" + toolName),
		Arguments: rawArgs,
	}
}

// makeServerConfig returns a minimal ServerConfig.
func makeServerConfig(id string, strategy gateway.AuthStrategy) *gateway.ServerConfig {
	return &gateway.ServerConfig{
		ID:       id,
		Name:     id,
		Strategy: strategy,
		Enabled:  true,
		Transport: gateway.TransportConfig{
			Type: gateway.TransportStreamableHTTP,
			URL:  "http://localhost:9999",
		},
	}
}

// runPipeline wires a Proxy with the given deps and runs a single tool call.
func runPipeline(t *testing.T, deps *gateway.Dependencies, serverID, toolName string, args map[string]any) *gateway.ToolCallContext {
	t.Helper()
	p := New(deps, Options{})
	tc := &gateway.ToolCallContext{
		RawRequest: makeRawRequest(serverID, toolName, args),
		RequestID:  "test-req-id",
	}
	ctx := context.WithValue(context.Background(), bearerTokenCtxKey, "test-token")
	p.pipeline(ctx, tc)
	return tc
}

// --- audit middleware ---

func TestAuditMiddleware_AlwaysEmits(t *testing.T) {
	t.Parallel()

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(nil, errors.New("bad token"))

	deps := &gateway.Dependencies{
		Authenticator:    auth,
		AuditLogger:      auditLogger,
		MetricsCollector: noopMetrics(t),
	}

	tc := runPipeline(t, deps, "svc", "tool", nil)
	assert.Error(t, tc.Err)
	// Emit is expected to be called once (verified by mock).
}

// --- auth middleware ---

func TestAuthMiddleware_MissingToken(t *testing.T) {
	t.Parallel()

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	deps := &gateway.Dependencies{
		AuditLogger:      auditLogger,
		MetricsCollector: noopMetrics(t),
	}

	p := New(deps, Options{})
	tc := &gateway.ToolCallContext{
		RawRequest: makeRawRequest("svc", "tool", nil),
		RequestID:  "req-1",
	}
	// No bearer token in context.
	p.pipeline(context.Background(), tc)
	require.Error(t, tc.Err)
	assert.ErrorIs(t, tc.Err, gateway.ErrUnauthenticated)
}

func TestAuthMiddleware_BadToken(t *testing.T) {
	t.Parallel()

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "bad-token").Return(nil, gateway.ErrUnauthenticated)

	deps := &gateway.Dependencies{
		Authenticator:    auth,
		AuditLogger:      auditLogger,
		MetricsCollector: noopMetrics(t),
	}

	p := New(deps, Options{})
	tc := &gateway.ToolCallContext{
		RawRequest: makeRawRequest("svc", "tool", nil),
		RequestID:  "req-2",
	}
	ctx := context.WithValue(context.Background(), bearerTokenCtxKey, "bad-token")
	p.pipeline(ctx, tc)
	require.Error(t, tc.Err)
	assert.ErrorIs(t, tc.Err, gateway.ErrUnauthenticated)
}

// --- policy middleware ---

func TestPolicyMiddleware_DenyShortCircuits(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "user@example.com", Type: gateway.IdentityHuman}
	serverCfg := makeServerConfig("svc", gateway.AuthStrategyStatic)

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(identity, nil)

	registry := mocks.NewMockServerRegistry(t)
	registry.EXPECT().Get(mock.Anything, "svc").Return(serverCfg, nil)

	policy := mocks.NewMockPolicyEngine(t)
	policy.EXPECT().Evaluate(mock.Anything, identity, mock.Anything).Return(
		&gateway.PolicyDecision{Action: gateway.ActionDeny, Rule: "deny-all", Reason: "test"},
		nil,
	)

	metrics := noopMetrics(t)

	deps := &gateway.Dependencies{
		Authenticator:    auth,
		ServerRegistry:   registry,
		PolicyEngine:     policy,
		AuditLogger:      auditLogger,
		MetricsCollector: metrics,
	}

	tc := runPipeline(t, deps, "svc", "tool", nil)
	require.Error(t, tc.Err)
	assert.ErrorIs(t, tc.Err, gateway.ErrPolicyDenied)
}

func TestPolicyMiddleware_FailOpenOnEvalError(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "user@example.com", Type: gateway.IdentityHuman}
	serverCfg := makeServerConfig("svc", gateway.AuthStrategyStatic)
	cred := &gateway.Credential{Type: gateway.CredTypeAPIKey, Value: []byte("key")}

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(identity, nil)

	registry := mocks.NewMockServerRegistry(t)
	registry.EXPECT().Get(mock.Anything, "svc").Return(serverCfg, nil)
	registry.EXPECT().Execute(mock.Anything, "svc", mock.Anything).RunAndReturn(
		func(ctx context.Context, id string, fn func() error) error { return fn() },
	)

	policy := mocks.NewMockPolicyEngine(t)
	policy.EXPECT().Evaluate(mock.Anything, identity, mock.Anything).Return(
		&gateway.PolicyDecision{Action: gateway.ActionAllow},
		errors.New("cel panic"),
	)

	resolver := mocks.NewMockCredentialResolver(t)
	resolver.EXPECT().Resolve(mock.Anything, identity, serverCfg).Return(cred, nil)

	metrics := noopMetrics(t)
	metrics.EXPECT().PolicyEvalError("svc", "tool")

	// Dispatch will fail (no real downstream); that's expected.
	deps := &gateway.Dependencies{
		Authenticator:      auth,
		ServerRegistry:     registry,
		PolicyEngine:       policy,
		CredentialResolver: resolver,
		AuditLogger:        auditLogger,
		MetricsCollector:   metrics,
	}

	tc := runPipeline(t, deps, "svc", "tool", nil)
	// PolicyEvalErr is set (fail-open), pipeline proceeds and fails at dispatch.
	assert.NotNil(t, tc.PolicyEvalErr)
}

// --- approval middleware ---

func TestApprovalMiddleware_RejectShortCircuits(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "user@example.com", Type: gateway.IdentityHuman}
	serverCfg := makeServerConfig("svc", gateway.AuthStrategyStatic)

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(identity, nil)

	registry := mocks.NewMockServerRegistry(t)
	registry.EXPECT().Get(mock.Anything, "svc").Return(serverCfg, nil)

	policy := mocks.NewMockPolicyEngine(t)
	policy.EXPECT().Evaluate(mock.Anything, identity, mock.Anything).Return(
		&gateway.PolicyDecision{
			Action:       gateway.ActionRequireApproval,
			Rule:         "require-approval",
			ApprovalSpec: &gateway.ApprovalSpec{Channel: "slack", Timeout: 0},
		}, nil,
	)

	svc := mocks.NewMockApprovalService(t)
	svc.EXPECT().Request(mock.Anything, mock.Anything).Return(
		&gateway.ApprovalDecision{Outcome: gateway.ApprovalRejected},
		nil,
	)

	metrics := noopMetrics(t)

	deps := &gateway.Dependencies{
		Authenticator:    auth,
		ServerRegistry:   registry,
		PolicyEngine:     policy,
		ApprovalService:  svc,
		AuditLogger:      auditLogger,
		MetricsCollector: metrics,
	}

	tc := runPipeline(t, deps, "svc", "tool", nil)
	require.Error(t, tc.Err)
	assert.ErrorIs(t, tc.Err, gateway.ErrApprovalRejected)
}

func TestApprovalMiddleware_Approved_ContinuesPipeline(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "user@example.com", Type: gateway.IdentityHuman}
	serverCfg := makeServerConfig("svc", gateway.AuthStrategyStatic)
	cred := &gateway.Credential{Type: gateway.CredTypeAPIKey, Value: []byte("key")}

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(identity, nil)

	registry := mocks.NewMockServerRegistry(t)
	registry.EXPECT().Get(mock.Anything, "svc").Return(serverCfg, nil)
	registry.EXPECT().Execute(mock.Anything, "svc", mock.Anything).RunAndReturn(
		func(ctx context.Context, id string, fn func() error) error { return fn() },
	)

	policy := mocks.NewMockPolicyEngine(t)
	policy.EXPECT().Evaluate(mock.Anything, identity, mock.Anything).Return(
		&gateway.PolicyDecision{
			Action:       gateway.ActionRequireApproval,
			ApprovalSpec: &gateway.ApprovalSpec{Channel: "slack"},
		}, nil,
	)

	svc := mocks.NewMockApprovalService(t)
	svc.EXPECT().Request(mock.Anything, mock.Anything).Return(
		&gateway.ApprovalDecision{Outcome: gateway.ApprovalApproved},
		nil,
	)

	resolver := mocks.NewMockCredentialResolver(t)
	resolver.EXPECT().Resolve(mock.Anything, identity, serverCfg).Return(cred, nil)

	metrics := noopMetrics(t)

	deps := &gateway.Dependencies{
		Authenticator:      auth,
		ServerRegistry:     registry,
		PolicyEngine:       policy,
		ApprovalService:    svc,
		CredentialResolver: resolver,
		AuditLogger:        auditLogger,
		MetricsCollector:   metrics,
	}

	tc := runPipeline(t, deps, "svc", "tool", nil)
	// Dispatch fails (no real server) but approval was processed.
	assert.NotNil(t, tc.Decision)
	assert.Equal(t, gateway.ActionRequireApproval, tc.Decision.Action)
}

// --- enrollment middleware ---

func TestEnrollmentMiddleware_NotEnrolled(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "user@example.com", Type: gateway.IdentityHuman}
	serverCfg := makeServerConfig("svc", gateway.AuthStrategyOAuth)

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(identity, nil)

	registry := mocks.NewMockServerRegistry(t)
	registry.EXPECT().Get(mock.Anything, "svc").Return(serverCfg, nil)

	policy := mocks.NewMockPolicyEngine(t)
	policy.EXPECT().Evaluate(mock.Anything, identity, mock.Anything).Return(
		&gateway.PolicyDecision{Action: gateway.ActionAllow}, nil,
	)

	enrollment := mocks.NewMockOAuthEnrollment(t)
	enrollment.EXPECT().IsEnrolled(mock.Anything, identity, "svc").Return(false, nil)
	enrollment.EXPECT().InitiateFlow(mock.Anything, identity, "svc").
		Return("https://provider.example.com/auth?code=123", nil)

	metrics := noopMetrics(t)

	deps := &gateway.Dependencies{
		Authenticator:    auth,
		ServerRegistry:   registry,
		PolicyEngine:     policy,
		OAuthEnrollment:  enrollment,
		AuditLogger:      auditLogger,
		MetricsCollector: metrics,
	}

	tc := runPipeline(t, deps, "svc", "tool", nil)
	require.Error(t, tc.Err)
	var enrollErr *gateway.EnrollmentRequiredError
	assert.True(t, errors.As(tc.Err, &enrollErr))
	assert.Equal(t, "svc", enrollErr.ServiceID)
}

// --- route middleware ---

func TestRouteMiddleware_UnknownServer(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "user@example.com"}

	auditLogger := mocks.NewMockAuditLogger(t)
	auditLogger.EXPECT().Emit(mock.Anything, mock.Anything).Return(nil)

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "test-token").Return(identity, nil)

	registry := mocks.NewMockServerRegistry(t)
	registry.EXPECT().Get(mock.Anything, "unknown").Return(nil, gateway.ErrServerNotFound)

	metrics := noopMetrics(t)

	deps := &gateway.Dependencies{
		Authenticator:    auth,
		ServerRegistry:   registry,
		AuditLogger:      auditLogger,
		MetricsCollector: metrics,
	}

	tc := runPipeline(t, deps, "unknown", "tool", nil)
	require.Error(t, tc.Err)
	assert.ErrorIs(t, tc.Err, gateway.ErrServerNotFound)
}

// --- helpers test ---

func TestToFromMCPName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		serverID string
		toolName string
		mcpName  string
	}{
		{"github", "create_pr", "github__create_pr"},
		{"my-server", "get_data", "my-server__get_data"},
	}
	for _, tc := range cases {
		namespaced := tc.serverID + "::" + tc.toolName
		assert.Equal(t, tc.mcpName, toMCPName(namespaced), "toMCPName(%q)", namespaced)
		gotServer, gotTool := fromMCPName(tc.mcpName)
		assert.Equal(t, tc.serverID, gotServer, "fromMCPName server for %q", tc.mcpName)
		assert.Equal(t, tc.toolName, gotTool, "fromMCPName tool for %q", tc.mcpName)
	}
}

func TestArgumentsSummary_Empty(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "(no arguments)", approvalArgumentsSummary(nil))
	assert.Equal(t, "(no arguments)", approvalArgumentsSummary(map[string]any{}))
}

func TestArgumentsSummary_NoValues(t *testing.T) {
	t.Parallel()
	summary := approvalArgumentsSummary(map[string]any{"name": "Alice", "age": 30})
	assert.Contains(t, summary, "name=")
	assert.Contains(t, summary, "age=")
	// Values must not appear.
	assert.NotContains(t, summary, "Alice")
	assert.NotContains(t, summary, "30")
}
