package store_test

// Full store tests require a live PostgreSQL instance and are run as part of
// the integration test suite (make integration-test).
//
// This file contains compile-time interface checks and lightweight unit tests
// that don't need a database connection.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/jphines/mcp-proxy/internal/store"
)

// TestAuditRow_Fields verifies the AuditRow struct has all fields needed
// for hash chain construction — compile-time structural check.
func TestAuditRow_Fields(t *testing.T) {
	r := store.AuditRow{
		EventID:          "01HZ...",
		InstanceID:       "proxy-1",
		Timestamp:        time.Now(),
		RequestID:        "req-abc",
		CallerSub:        "jane@ro.com",
		CallerType:       "human",
		CallerGroups:     []string{"engineering"},
		CallerSessionID:  "sid-xyz",
		ToolNamespaced:   "github::list_repos",
		ArgumentsHash:    "sha256:abc",
		CredentialRef:    "proxy/github-token",
		Decision:         "allow",
		PolicyRule:       "default-allow",
		PolicyReason:     "no matching rule",
		Workspace:        "production",
		DownstreamStatus: 200,
		LatencyMs:        12,
		DownstreamMs:     8,
		PrevHash:         "genesis",
		Hash:             "sha256:xyz",
	}
	assert.NotEmpty(t, r.EventID)
	assert.Equal(t, "proxy-1", r.InstanceID)
}

// TestApprovalRecord_Fields verifies the ApprovalRecord struct — compile check.
func TestApprovalRecord_Fields(t *testing.T) {
	now := time.Now()
	r := store.ApprovalRecord{
		RequestID:        "req-1",
		ToolNamespaced:   "infra::scale_down",
		ArgumentsSummary: "cluster=prod-east-1, replicas=0",
		CallerSub:        "jane@ro.com",
		CallerType:       "human",
		PolicyRule:       "require-approval-tier4",
		PolicyReason:     "tier-4 action",
		Channel:          "slack",
		TimeoutSeconds:   300,
		Status:           "pending",
		CreatedAt:        now,
	}
	assert.Equal(t, "pending", r.Status)
	assert.Nil(t, r.DecidedAt)
}

// TestSession_Fields verifies the Session struct — compile check.
func TestSession_Fields(t *testing.T) {
	s := store.Session{
		ID:         "jane@ro.com:sid-xyz",
		CallerSub:  "jane@ro.com",
		CallerType: "human",
		SessionID:  "sid-xyz",
		Workspace:  "production",
		CreatedAt:  time.Now(),
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	assert.Equal(t, "jane@ro.com", s.CallerSub)
	assert.Equal(t, "production", s.Workspace)
}

// TestErrNotFound_IsExported verifies ErrNotFound is exported for callers.
func TestErrNotFound_IsExported(t *testing.T) {
	assert.NotNil(t, store.ErrNotFound)
}
