package audit

import (
	"context"

	"github.com/jphines/mcp-proxy/gateway"
)

// NoopLogger is a gateway.AuditLogger that silently discards all events.
// Use it in unit tests that do not need audit verification.
type NoopLogger struct{}

// Emit does nothing and returns nil.
func (n *NoopLogger) Emit(_ context.Context, _ *gateway.AuditEvent) error { return nil }

// VerifyChain does nothing and returns nil.
func (n *NoopLogger) VerifyChain(_ context.Context, _ string) error { return nil }

var _ gateway.AuditLogger = (*NoopLogger)(nil)
