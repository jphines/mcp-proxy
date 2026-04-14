package audit_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/audit"
	"github.com/ro-eng/mcp-proxy/internal/store"
)

// --- stub CloudWatch client ---

type stubCWClient struct {
	mu     sync.Mutex
	calls  []*cloudwatchlogs.PutLogEventsInput
	errFn  func(n int) error // called with 0-based call index
}

func (s *stubCWClient) PutLogEvents(_ context.Context, input *cloudwatchlogs.PutLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := len(s.calls)
	s.calls = append(s.calls, input)
	if s.errFn != nil {
		return nil, s.errFn(idx)
	}
	return &cloudwatchlogs.PutLogEventsOutput{}, nil
}

func (s *stubCWClient) allEvents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.calls {
		for _, e := range c.LogEvents {
			if e.Message != nil {
				out = append(out, *e.Message)
			}
		}
	}
	return out
}

// --- helpers ---

func newLogger(t *testing.T, client *stubCWClient) *audit.CloudWatchLogger {
	t.Helper()
	return audit.NewCloudWatchLogger(client, audit.CloudWatchOptions{
		LogGroupName:  "test-group",
		LogStreamName: "test-stream",
		InstanceID:    "inst-1",
		Workspace:     "test",
		GenesisHash:   "genesis",
		FlushInterval: 20 * time.Millisecond,
	})
}

func makeEvent(tool string) *gateway.AuditEvent {
	return &gateway.AuditEvent{
		CallerSubject: "user@test.com",
		CallerType:    gateway.IdentityHuman,
		ToolNamespaced: tool,
		Decision:      gateway.ActionAllow,
		Timestamp:     time.Now().UTC(),
	}
}

// --- tests ---

func TestCloudWatchLogger_EmitFlushesEvents(t *testing.T) {
	t.Parallel()
	stub := &stubCWClient{}
	logger := newLogger(t, stub)
	defer logger.Close()

	require.NoError(t, logger.Emit(context.Background(), makeEvent("svc::read")))
	require.NoError(t, logger.Emit(context.Background(), makeEvent("svc::write")))

	// Wait for flush.
	time.Sleep(60 * time.Millisecond)

	events := stub.allEvents()
	require.Len(t, events, 2)

	var e1, e2 gateway.AuditEvent
	require.NoError(t, json.Unmarshal([]byte(events[0]), &e1))
	require.NoError(t, json.Unmarshal([]byte(events[1]), &e2))
	assert.Equal(t, "svc::read", e1.ToolNamespaced)
	assert.Equal(t, "svc::write", e2.ToolNamespaced)
}

func TestCloudWatchLogger_HashChainIsLinked(t *testing.T) {
	t.Parallel()
	stub := &stubCWClient{}
	logger := newLogger(t, stub)
	defer logger.Close()

	ctx := context.Background()
	require.NoError(t, logger.Emit(ctx, makeEvent("svc::a")))
	require.NoError(t, logger.Emit(ctx, makeEvent("svc::b")))
	require.NoError(t, logger.Emit(ctx, makeEvent("svc::c")))

	time.Sleep(60 * time.Millisecond)

	messages := stub.allEvents()
	require.Len(t, messages, 3)

	var events [3]gateway.AuditEvent
	for i, m := range messages {
		require.NoError(t, json.Unmarshal([]byte(m), &events[i]))
	}

	// First event's PrevHash must be the genesis seed.
	assert.Equal(t, "genesis", events[0].PrevHash)
	// Each event's PrevHash must equal the previous event's Hash.
	assert.Equal(t, events[0].Hash, events[1].PrevHash)
	assert.Equal(t, events[1].Hash, events[2].PrevHash)
	// Hash must not be empty.
	assert.NotEmpty(t, events[0].Hash)
	assert.NotEmpty(t, events[1].Hash)
	assert.NotEmpty(t, events[2].Hash)
}

func TestCloudWatchLogger_AssignsEventIDIfMissing(t *testing.T) {
	t.Parallel()
	stub := &stubCWClient{}
	logger := newLogger(t, stub)
	defer logger.Close()

	event := makeEvent("svc::x")
	event.EventID = "" // ensure empty

	require.NoError(t, logger.Emit(context.Background(), event))

	assert.NotEmpty(t, event.EventID, "Emit must assign a ULID when EventID is empty")
}

func TestCloudWatchLogger_CloseFlushesRemainingEvents(t *testing.T) {
	t.Parallel()
	// Use a very long flush interval so Close() is what triggers the flush.
	stub := &stubCWClient{}
	logger := audit.NewCloudWatchLogger(stub, audit.CloudWatchOptions{
		LogGroupName:  "g",
		LogStreamName: "s",
		GenesisHash:   "genesis",
		FlushInterval: 10 * time.Second,
	})

	require.NoError(t, logger.Emit(context.Background(), makeEvent("svc::x")))
	logger.Close() // must flush before returning

	assert.Len(t, stub.allEvents(), 1)
}

func TestNoopLogger(t *testing.T) {
	t.Parallel()
	l := &audit.NoopLogger{}
	require.NoError(t, l.Emit(context.Background(), makeEvent("svc::x")))
	require.NoError(t, l.VerifyChain(context.Background(), "inst"))
}

func TestComputeHash_Deterministic(t *testing.T) {
	t.Parallel()
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	e1 := &gateway.AuditEvent{EventID: "fixed-id", ToolNamespaced: "svc::determinism", Timestamp: fixedTime}
	e2 := &gateway.AuditEvent{EventID: "fixed-id", ToolNamespaced: "svc::determinism", Timestamp: fixedTime}

	audit.ComputeHash(e1, "prev")
	audit.ComputeHash(e2, "prev")

	assert.Equal(t, e1.Hash, e2.Hash, "same input must produce same hash")
	assert.NotEmpty(t, e1.Hash)
}

func TestComputeHash_ChangesWithPrevHash(t *testing.T) {
	t.Parallel()
	e1 := makeEvent("svc::x")
	e1.EventID = "id1"
	e2 := makeEvent("svc::x")
	e2.EventID = "id1"

	audit.ComputeHash(e1, "prevA")
	audit.ComputeHash(e2, "prevB")

	assert.NotEqual(t, e1.Hash, e2.Hash)
}

// --- RowHash / chain integrity ---

func TestRowHash_MatchesComputeHash(t *testing.T) {
	t.Parallel()
	fixedTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	row := &store.AuditRow{
		EventID:        "evt-1",
		RequestID:      "req-1",
		Timestamp:      fixedTime,
		CallerSub:      "user@example.com",
		CallerType:     "human",
		ToolNamespaced: "svc::tool",
		Decision:       "allow",
	}

	// Compute via RowHash.
	rowHash := audit.RowHash(row, "genesis")

	// Reproduce via ComputeHash applied to the equivalent AuditEvent.
	event := &gateway.AuditEvent{
		EventID:        row.EventID,
		RequestID:      row.RequestID,
		Timestamp:      row.Timestamp,
		CallerSubject:  row.CallerSub,
		CallerType:     gateway.IdentityType(row.CallerType),
		ToolNamespaced: row.ToolNamespaced,
		Decision:       gateway.PolicyAction(row.Decision),
	}
	audit.ComputeHash(event, "genesis")

	assert.Equal(t, event.Hash, rowHash, "RowHash must equal ComputeHash on equivalent AuditEvent")
	assert.NotEmpty(t, rowHash)
}

func TestRowHash_DifferentPrevHashProducesDifferentHash(t *testing.T) {
	t.Parallel()
	row := &store.AuditRow{
		EventID:   "evt-2",
		RequestID: "req-2",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	h1 := audit.RowHash(row, "prev-A")
	h2 := audit.RowHash(row, "prev-B")
	assert.NotEqual(t, h1, h2)
}

func TestRowHash_Deterministic(t *testing.T) {
	t.Parallel()
	row := &store.AuditRow{
		EventID:        "evt-det",
		Timestamp:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ToolNamespaced: "svc::determinism",
	}
	h1 := audit.RowHash(row, "p")
	h2 := audit.RowHash(row, "p")
	assert.Equal(t, h1, h2)
}
