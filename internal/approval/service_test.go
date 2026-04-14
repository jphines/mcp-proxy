package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/approval"
)

func newRequest(id string, timeout time.Duration) *gateway.ApprovalRequest {
	return &gateway.ApprovalRequest{
		RequestID:        id,
		ToolNamespaced:   "svc::tool",
		CallerSubject:    "user@test.com",
		CallerType:       gateway.IdentityHuman,
		PolicyRule:       "require-approval-tier4",
		PolicyReason:     "tier 4 tool requires HITL",
		ArgumentsSummary: "{patient_id: <id>}",
		CreatedAt:        time.Now().UTC(),
		Spec:             gateway.ApprovalSpec{Timeout: timeout},
	}
}

// TestApprovalService_ApproveUnblocks verifies that a concurrent Decide(approved) unblocks Request.
func TestApprovalService_ApproveUnblocks(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	req := newRequest("req-1", 5*time.Second)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = svc.Decide(context.Background(), &gateway.ApprovalDecision{
			RequestID: "req-1",
			Outcome:   gateway.ApprovalApproved,
			DecidedAt: time.Now().UTC(),
		})
	}()

	decision, err := svc.Request(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, gateway.ApprovalApproved, decision.Outcome)
}

// TestApprovalService_RejectReturnsError verifies that rejection is propagated.
func TestApprovalService_RejectReturnsError(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	req := newRequest("req-2", 5*time.Second)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = svc.Decide(context.Background(), &gateway.ApprovalDecision{
			RequestID: "req-2",
			Outcome:   gateway.ApprovalRejected,
			DecidedAt: time.Now().UTC(),
		})
	}()

	_, err := svc.Request(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrApprovalRejected))
}

// TestApprovalService_TimeoutReturnsError verifies that the TTL fires.
func TestApprovalService_TimeoutReturnsError(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	req := newRequest("req-3", 30*time.Millisecond)

	_, err := svc.Request(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrApprovalTimedOut))
}

// TestApprovalService_ContextCancelledReturnsError verifies context cancellation.
func TestApprovalService_ContextCancelledReturnsError(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	req := newRequest("req-4", 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := svc.Request(ctx, req)
	require.Error(t, err)
}

// TestApprovalService_DecideUnknownID returns an error for unknown requests.
func TestApprovalService_DecideUnknownID(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	err := svc.Decide(context.Background(), &gateway.ApprovalDecision{
		RequestID: "nonexistent",
		Outcome:   gateway.ApprovalApproved,
	})
	require.Error(t, err)
}

// TestApprovalService_ConcurrentRequests verifies multiple independent requests.
func TestApprovalService_ConcurrentRequests(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)

	ids := []string{"a", "b", "c"}
	results := make(chan error, len(ids))

	for _, id := range ids {
		id := id
		req := newRequest(id, 2*time.Second)
		go func() {
			_, err := svc.Request(context.Background(), req)
			results <- err
		}()
	}

	time.Sleep(20 * time.Millisecond)
	for _, id := range ids {
		require.NoError(t, svc.Decide(context.Background(), &gateway.ApprovalDecision{
			RequestID: id,
			Outcome:   gateway.ApprovalApproved,
		}))
	}

	for range ids {
		require.NoError(t, <-results)
	}
}
