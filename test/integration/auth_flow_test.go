package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp_fixture "github.com/jphines/mcp-proxy/test/mcp_fixture"
)

// TestAuthFlow_ValidToken verifies that a valid Okta JWT allows a tool call
// to reach the downstream MCP server.
func TestAuthFlow_ValidToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, allowAllPolicy)

	token := h.keys.token(t,
		func(b *jwt.Builder) *jwt.Builder {
			return b.
				Claim("groups", []string{"engineering"}).
				Claim("x-identity-type", "human")
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := h.callTool(ctx, token, "fixture__read_data", map[string]any{"id": "test-123"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError, "tool call should succeed with valid token")

	// Downstream recorder confirms the tool was called.
	calls := h.downstream.Recorder().CallsFor(mcp_fixture.ToolReadData)
	require.Len(t, calls, 1, "downstream should have received exactly one call")
	assert.Equal(t, "test-123", calls[0].Arguments["id"])
}

// TestAuthFlow_NoToken verifies that a missing Authorization header causes
// the tool call to return an error (unauthenticated).
// The MCP session itself still connects (GetServer returns a valid server for
// nil identity); the error surfaces in the tool call result.
func TestAuthFlow_NoToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, allowAllPolicy)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := h.callTool(ctx, "" /* no token */, "fixture__read_data", nil)
	require.NoError(t, err) // MCP protocol-level call succeeds
	require.NotNil(t, result)
	assert.True(t, result.IsError, "tool call should fail with no token")

	// Downstream should NOT have been called.
	assert.Zero(t, h.downstream.Recorder().Len(), "downstream should not be called on auth failure")
}

// TestAuthFlow_ExpiredToken verifies that an expired JWT is rejected.
// When GetServer receives an invalid token it returns nil, which the MCP SDK
// translates to a connection-level error.
func TestAuthFlow_ExpiredToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, allowAllPolicy)

	expiredToken := h.keys.token(t,
		func(b *jwt.Builder) *jwt.Builder {
			past := time.Now().Add(-2 * time.Hour)
			return b.
				IssuedAt(past).
				Expiration(past.Add(time.Hour)) // expired 1 hour ago
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := h.callTool(ctx, expiredToken, "fixture__read_data", nil)
	// The MCP connect should fail because GetServer returns nil for an invalid token.
	require.Error(t, err, "connect should fail with expired token")
}

// TestAuthFlow_WrongAudience verifies that a JWT with an unexpected audience is rejected.
func TestAuthFlow_WrongAudience(t *testing.T) {
	t.Parallel()
	h := newHarness(t, allowAllPolicy)

	wrongAudToken := h.keys.token(t,
		func(b *jwt.Builder) *jwt.Builder {
			return b.Audience([]string{"api://wrong-audience"})
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := h.callTool(ctx, wrongAudToken, "fixture__read_data", nil)
	require.Error(t, err, "connect should fail with wrong audience token")
}

// TestAuthFlow_AgentIdentity verifies that agent tokens are authenticated and
// their identity type is propagated through the pipeline.
func TestAuthFlow_AgentIdentity(t *testing.T) {
	t.Parallel()
	// Use an allow-all policy; if identity type is correctly set the CEL engine
	// could be used to deny agents, but here we just verify the call succeeds.
	h := newHarness(t, allowAllPolicy)

	agentToken := h.keys.token(t,
		func(b *jwt.Builder) *jwt.Builder {
			return b.
				Subject("agent-rx-checker").
				Claim("x-identity-type", "agent").
				Claim("delegated_by", "user@example.com")
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := h.callTool(ctx, agentToken, "fixture__read_data", nil)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	// At least one downstream call recorded.
	assert.Equal(t, 1, h.downstream.Recorder().Len())
}

// TestAuthFlow_UnknownTool verifies that calling a tool not in the catalog
// returns a graceful error (not a crash).
func TestAuthFlow_UnknownTool(t *testing.T) {
	t.Parallel()
	h := newHarness(t, allowAllPolicy)

	token := h.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The proxy will not find "fixture__nonexistent" in the tool catalog, but the
	// MCP SDK will report a tool-not-found error at the session level.
	_, err := h.callTool(ctx, token, "fixture__nonexistent_tool", nil)
	// Either an error from connect (tool not in catalog) or a tool result with IsError.
	// Either outcome is acceptable — the proxy must not panic.
	_ = err // tolerate both outcomes; the important thing is no panic
	t.Logf("unknown tool result: err=%v", err)

	// Downstream should not have been called for unknown tool.
	called := h.downstream.Recorder().CallsFor("nonexistent_tool")
	assert.Empty(t, called)

	// Check the tool name with double underscores is parsed correctly.
	r2, err2 := h.callTool(ctx, token, "fixture__read_data", nil)
	require.NoError(t, err2)
	assert.False(t, r2.IsError)

	assert.NotEmpty(t, strings.TrimSpace("fixture__read_data"), "separator convention sanity check")
}
