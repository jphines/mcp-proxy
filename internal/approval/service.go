// Package approval implements the gateway.ApprovalService interface.
// Pending approval requests block on an in-process channel; the Slack webhook
// callback delivers the human's decision.
package approval

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// Service implements gateway.ApprovalService using an in-memory pending map.
// Each Request() call blocks until a decision arrives via Decide() or the timeout fires.
type Service struct {
	slack  *SlackSender // may be nil for tests
	mu     sync.Mutex
	pending map[string]chan *gateway.ApprovalDecision
}

// NewService creates an approval Service. sender may be nil to disable Slack notifications.
func NewService(sender *SlackSender) *Service {
	return &Service{
		slack:   sender,
		pending: make(map[string]chan *gateway.ApprovalDecision),
	}
}

// Request sends an approval request to Slack (if configured) and blocks until a
// decision arrives or the context deadline / timeout fires.
func (s *Service) Request(ctx context.Context, req *gateway.ApprovalRequest) (*gateway.ApprovalDecision, error) {
	ch := make(chan *gateway.ApprovalDecision, 1)

	s.mu.Lock()
	s.pending[req.RequestID] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, req.RequestID)
		s.mu.Unlock()
	}()

	if s.slack != nil {
		if err := s.slack.Send(ctx, req); err != nil {
			// Non-fatal: log the error but continue waiting. The approver may
			// still deliver a decision via another channel.
			_ = err
		}
	}

	// Determine timeout: use Spec.Timeout if set, otherwise fall back to the context.
	var timer *time.Timer
	var timerCh <-chan time.Time
	if req.Spec.Timeout > 0 {
		timer = time.NewTimer(req.Spec.Timeout)
		defer timer.Stop()
		timerCh = timer.C
	}

	select {
	case decision := <-ch:
		if decision.Outcome == gateway.ApprovalRejected {
			return decision, gateway.ErrApprovalRejected
		}
		return decision, nil
	case <-timerCh:
		return &gateway.ApprovalDecision{
			RequestID: req.RequestID,
			Outcome:   gateway.ApprovalTimedOut,
			DecidedAt: time.Now().UTC(),
		}, gateway.ErrApprovalTimedOut
	case <-ctx.Done():
		return nil, fmt.Errorf("approval: context cancelled: %w", ctx.Err())
	}
}

// Decide delivers a decision for a pending request.
// Returns an error if the requestID is unknown or has already been decided.
func (s *Service) Decide(ctx context.Context, decision *gateway.ApprovalDecision) error {
	s.mu.Lock()
	ch, ok := s.pending[decision.RequestID]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("approval: no pending request with ID %q", decision.RequestID)
	}

	select {
	case ch <- decision:
		return nil
	default:
		return fmt.Errorf("approval: decision already delivered for request %q", decision.RequestID)
	}
}

var _ gateway.ApprovalService = (*Service)(nil)

// sentinel for unused errors.go reference
var _ = errors.New
