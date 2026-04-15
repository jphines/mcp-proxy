package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/approval"
	mcp_fixture "github.com/ro-eng/mcp-proxy/test/mcp_fixture"
)

// denyTier3Policy denies tool calls on servers with data_tier >= 3.
const denyTier3Policy = `rules:
  - id: deny-tier3
    priority: 1
    condition: "tool.tier >= 3"
    action: deny
    reason: "tier 3+ operations denied in test"
    audit_level: full
  - id: allow-all
    priority: 999
    condition: "true"
    action: allow
    audit_level: standard
`

// requireApprovalPolicy requires HITL approval for every call (2s timeout).
const requireApprovalPolicy = `rules:
  - id: require-approval-all
    priority: 1
    condition: "true"
    action: require_approval
    reason: "all calls require approval in test"
    audit_level: full
    approval:
      channel: slack
      timeout: 2s
`

// logAndAllowPolicy uses a composing log rule followed by an allow.
const logAndAllowPolicy = `rules:
  - id: log-all-calls
    priority: 10
    condition: "true"
    action: log
    reason: "observability test"
    audit_level: full
  - id: allow-all
    priority: 999
    condition: "true"
    action: allow
    audit_level: standard
`

// ── interceptApprovalService ──────────────────────────────────────────────────

// interceptApprovalService wraps a real approval.Service and exposes each
// pending request ID to the test via a buffered channel.
type interceptApprovalService struct {
	inner    *approval.Service
	requests chan string // receives requestID for each pending Request() call
}

func newInterceptApprovalService() *interceptApprovalService {
	return &interceptApprovalService{
		inner:    approval.NewService(nil),
		requests: make(chan string, 10),
	}
}

func (s *interceptApprovalService) Request(ctx context.Context, req *gateway.ApprovalRequest) (*gateway.ApprovalDecision, error) {
	select {
	case s.requests <- req.RequestID:
	default: // drop if full; test timeout will catch it
	}
	return s.inner.Request(ctx, req)
}

func (s *interceptApprovalService) Decide(ctx context.Context, d *gateway.ApprovalDecision) error {
	return s.inner.Decide(ctx, d)
}

var _ gateway.ApprovalService = (*interceptApprovalService)(nil)

// ── callResult bundles tool call output for channel passing ──────────────────

type callResult struct {
	result *mcp.CallToolResult
	err    error
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestPolicyFlow_Allow verifies that an allow policy permits tool calls and
// they reach the downstream server.
func TestPolicyFlow_Allow(t *testing.T) {
	t.Parallel()
	h := newHarness(t, allowAllPolicy)
	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := h.callTool(ctx, token, "fixture__search", map[string]any{"query": "hello"})
	require.NoError(t, err)
	assert.False(t, result.IsError, "allow policy: tool call should succeed")

	calls := h.downstream.Recorder().CallsFor(mcp_fixture.ToolSearch)
	require.Len(t, calls, 1)
	assert.Equal(t, "hello", calls[0].Arguments["query"])
}

// TestPolicyFlow_Deny verifies that a deny rule short-circuits the pipeline and
// the downstream server is never called.
func TestPolicyFlow_Deny(t *testing.T) {
	t.Parallel()
	// fixture server has data_tier: 4, so tier >= 3 fires.
	h := newHarness(t, denyTier3Policy)
	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := h.callTool(ctx, token, "fixture__write_data", map[string]any{"payload": "test"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError, "deny policy: result should have IsError=true")
	assert.Empty(t, h.downstream.Recorder().CallsFor(mcp_fixture.ToolWriteData),
		"downstream should NOT be called when policy denies")
}

// TestPolicyFlow_RequireApproval_Approved verifies that when a require_approval
// rule fires, the pipeline blocks until Decide(Approved) is called, then the
// tool call completes and the downstream receives the request.
func TestPolicyFlow_RequireApproval_Approved(t *testing.T) {
	t.Parallel()

	interceptSvc := newInterceptApprovalService()
	h := newHarness(t, requireApprovalPolicy, harnessOptions{
		approvalSvc:      interceptSvc,
		innerApprovalSvc: interceptSvc.inner,
	})
	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Launch the tool call; it blocks inside the pipeline awaiting approval.
	done := make(chan callResult, 1)
	go func() {
		r, e := h.callTool(ctx, token, "fixture__read_data", map[string]any{"id": "approve-me"})
		done <- callResult{r, e}
	}()

	// Wait for the approval request to register, then approve it.
	var requestID string
	select {
	case requestID = <-interceptSvc.requests:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for approval request to register")
	}

	require.NoError(t, interceptSvc.inner.Decide(ctx, &gateway.ApprovalDecision{
		RequestID: requestID,
		Outcome:   gateway.ApprovalApproved,
		DecidedAt: time.Now().UTC(),
	}))

	// The tool call should now complete successfully.
	select {
	case res := <-done:
		require.NoError(t, res.err)
		assert.False(t, res.result.IsError, "approved call should succeed")
	case <-time.After(10 * time.Second):
		t.Fatal("tool call did not complete after approval")
	}

	assert.Equal(t, 1, h.downstream.Recorder().Len(),
		"downstream should be called exactly once after approval")
}

// TestPolicyFlow_RequireApproval_Rejected verifies that a rejected approval
// returns an error result and the downstream is never called.
func TestPolicyFlow_RequireApproval_Rejected(t *testing.T) {
	t.Parallel()

	interceptSvc := newInterceptApprovalService()
	h := newHarness(t, requireApprovalPolicy, harnessOptions{
		approvalSvc:      interceptSvc,
		innerApprovalSvc: interceptSvc.inner,
	})
	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan callResult, 1)
	go func() {
		r, e := h.callTool(ctx, token, "fixture__delete_data", map[string]any{"id": "reject-me"})
		done <- callResult{r, e}
	}()

	var requestID string
	select {
	case requestID = <-interceptSvc.requests:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for approval request")
	}

	require.NoError(t, interceptSvc.inner.Decide(ctx, &gateway.ApprovalDecision{
		RequestID: requestID,
		Outcome:   gateway.ApprovalRejected,
		DecidedAt: time.Now().UTC(),
	}))

	select {
	case res := <-done:
		require.NoError(t, res.err)
		require.NotNil(t, res.result)
		assert.True(t, res.result.IsError, "rejected approval should return error result")
	case <-time.After(10 * time.Second):
		t.Fatal("tool call did not complete after rejection")
	}

	assert.Zero(t, h.downstream.Recorder().Len(), "downstream must not be called after rejection")
}

// TestPolicyFlow_Timeout verifies that an unanswered approval request times out
// and the tool call returns an error result without panicking.
func TestPolicyFlow_Timeout(t *testing.T) {
	t.Parallel()

	shortTimeoutPolicy := `rules:
  - id: require-approval-short
    priority: 1
    condition: "true"
    action: require_approval
    reason: "short timeout test"
    audit_level: full
    approval:
      channel: slack
      timeout: 500ms
`
	h := newHarness(t, shortTimeoutPolicy)
	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// No approval delivered — the 500ms policy timeout will fire.
	result, err := h.callTool(ctx, token, "fixture__read_data", nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError, "timed-out approval should produce an error result")
	assert.Zero(t, h.downstream.Recorder().Len())
}

// TestPolicyFlow_LogCompose verifies that log rules compose with an allow rule
// and the tool call reaches the downstream server.
func TestPolicyFlow_LogCompose(t *testing.T) {
	t.Parallel()
	h := newHarness(t, logAndAllowPolicy)
	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := h.callTool(ctx, token, "fixture__search", map[string]any{"query": "compose"})
	require.NoError(t, err)
	assert.False(t, result.IsError, "log+allow: tool call should succeed")
	assert.Equal(t, 1, h.downstream.Recorder().Len())
}
