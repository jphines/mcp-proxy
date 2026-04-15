package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/audit"
	"github.com/ro-eng/mcp-proxy/internal/store"
)

// TestAuditChain_Integrity inserts a chain of audit events and verifies that
// VerifyChain confirms the chain is intact.
func TestAuditChain_Integrity(t *testing.T) {
	if testDB == nil {
		t.Skip("PostgreSQL container unavailable; skipping audit chain test")
	}

	ctx := context.Background()
	instanceID := "test-instance-integrity-" + ulid.Make().String()

	const numEvents = 10
	prevHash := "genesis-" + instanceID

	for i := 0; i < numEvents; i++ {
		row := &store.AuditRow{
			EventID:        ulid.Make().String(),
			InstanceID:     instanceID,
			Timestamp:      time.Now().UTC(),
			RequestID:      fmt.Sprintf("req-%d", i),
			CallerSub:      "test-user@example.com",
			CallerType:     string(gateway.IdentityHuman),
			CallerGroups:   []string{"engineering"},
			ToolNamespaced: "fixture::read_data",
			ArgumentsHash:  fmt.Sprintf("hash-%d", i),
			Decision:       string(gateway.ActionAllow),
			Workspace:      "test",
		}

		// Compute hash using the same algorithm as the production chain.
		event := rowToAuditEvent(row)
		audit.ComputeHash(event, prevHash)
		row.PrevHash = event.PrevHash
		row.Hash = event.Hash
		prevHash = row.Hash

		require.NoError(t, testDB.InsertAuditEvent(ctx, row),
			"inserting event %d", i)
	}

	// VerifyChain should confirm all 10 events are intact.
	err := testDB.VerifyChain(ctx, instanceID, audit.RowHash)
	require.NoError(t, err, "chain should be intact after sequential writes")
}

// TestAuditChain_TamperDetection inserts a chain, modifies a row's hash
// directly in the database, and verifies that VerifyChain detects the tamper.
func TestAuditChain_TamperDetection(t *testing.T) {
	if testDB == nil {
		t.Skip("PostgreSQL container unavailable; skipping audit chain tamper test")
	}

	ctx := context.Background()
	instanceID := "test-instance-tamper-" + ulid.Make().String()

	var rows []*store.AuditRow
	prevHash := "genesis-" + instanceID

	// Insert 5 events.
	for i := 0; i < 5; i++ {
		row := &store.AuditRow{
			EventID:        ulid.Make().String(),
			InstanceID:     instanceID,
			Timestamp:      time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
			RequestID:      fmt.Sprintf("req-%d", i),
			CallerSub:      "test-user@example.com",
			CallerType:     string(gateway.IdentityHuman),
			CallerGroups:   []string{"engineering"},
			ToolNamespaced: "fixture::read_data",
			ArgumentsHash:  fmt.Sprintf("hash-%d", i),
			Decision:       string(gateway.ActionAllow),
			Workspace:      "test",
		}

		event := rowToAuditEvent(row)
		audit.ComputeHash(event, prevHash)
		row.PrevHash = event.PrevHash
		row.Hash = event.Hash
		prevHash = row.Hash

		require.NoError(t, testDB.InsertAuditEvent(ctx, row))
		rows = append(rows, row)
	}

	// Verify the chain is clean before tampering.
	require.NoError(t, testDB.VerifyChain(ctx, instanceID, audit.RowHash),
		"chain should be clean before tamper")

	// Tamper with the 3rd event's hash directly in the database.
	tamperTarget := rows[2].EventID
	_, err := testDB.Pool().Exec(ctx,
		`UPDATE audit_events SET hash = 'tampered-hash-value' WHERE event_id = $1`,
		tamperTarget,
	)
	require.NoError(t, err, "update for tamper must succeed")

	// VerifyChain should now detect the broken link.
	verifyErr := testDB.VerifyChain(ctx, instanceID, audit.RowHash)
	require.Error(t, verifyErr, "VerifyChain should detect the tampered hash")
	assert.Contains(t, verifyErr.Error(), "hash mismatch",
		"error should describe the mismatch at the tampered event")
}

// TestAuditChain_EmptyInstance verifies that VerifyChain returns no error for
// an instance that has no events yet (genesis / first-run case).
func TestAuditChain_EmptyInstance(t *testing.T) {
	if testDB == nil {
		t.Skip("PostgreSQL container unavailable")
	}

	ctx := context.Background()
	instanceID := "test-instance-empty-" + ulid.Make().String()

	// VerifyChain on a non-existent instance should return nil (empty range).
	err := testDB.VerifyChain(ctx, instanceID, audit.RowHash)
	require.NoError(t, err, "empty instance chain should be considered valid")
}

// TestAuditChain_GenesisUpsert verifies that UpsertChainGenesis is idempotent:
// calling it twice returns the same seed both times.
func TestAuditChain_GenesisUpsert(t *testing.T) {
	if testDB == nil {
		t.Skip("PostgreSQL container unavailable")
	}

	ctx := context.Background()
	instanceID := "test-instance-genesis-" + ulid.Make().String()

	seed1, err := testDB.UpsertChainGenesis(ctx, instanceID, "seed-value-abc")
	require.NoError(t, err)
	assert.Equal(t, "seed-value-abc", seed1, "first upsert should return the provided seed")

	// Second call with a different seed should still return the original.
	seed2, err := testDB.UpsertChainGenesis(ctx, instanceID, "different-seed")
	require.NoError(t, err)
	assert.Equal(t, seed1, seed2, "second upsert must return the original seed (idempotent)")
}

// ── helper ────────────────────────────────────────────────────────────────────

// rowToAuditEvent converts a store.AuditRow to a gateway.AuditEvent for hashing.
// Mirrors audit.rowToEvent (not exported, so we duplicate the minimal version here).
func rowToAuditEvent(r *store.AuditRow) *gateway.AuditEvent {
	return &gateway.AuditEvent{
		EventID:           r.EventID,
		Timestamp:         r.Timestamp,
		RequestID:         r.RequestID,
		CallerSubject:     r.CallerSub,
		CallerType:        gateway.IdentityType(r.CallerType),
		CallerGroups:      r.CallerGroups,
		CallerSessionID:   r.CallerSessionID,
		ToolNamespaced:    r.ToolNamespaced,
		ArgumentsHash:     r.ArgumentsHash,
		CredentialRef:     r.CredentialRef,
		Decision:          gateway.PolicyAction(r.Decision),
		PolicyRule:        r.PolicyRule,
		PolicyReason:      r.PolicyReason,
		Workspace:         r.Workspace,
		DownstreamStatus:  r.DownstreamStatus,
		LatencyMs:         r.LatencyMs,
		DownstreamMs:      r.DownstreamMs,
		RedactionsApplied: r.RedactionsApplied,
		PolicyEvalError:   r.PolicyEvalError,
	}
}
