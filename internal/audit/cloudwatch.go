package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/oklog/ulid/v2"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/store"
)

// cwClient is a minimal interface over the CloudWatch Logs SDK client,
// enabling injection of test doubles.
type cwClient interface {
	PutLogEvents(ctx context.Context, params *cloudwatchlogs.PutLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
}

// CloudWatchLogger implements gateway.AuditLogger by:
//  1. Computing SHA-256 hash chain in memory.
//  2. Batching events and flushing to a CloudWatch Logs stream every flushInterval.
//  3. Optionally writing to PostgreSQL via store.DB for durable VerifyChain support.
type CloudWatchLogger struct {
	client        cwClient
	db            *store.DB   // nil = CloudWatch-only; VerifyChain returns ErrNotSupported
	logGroupName  string
	logStreamName string
	instanceID    string
	workspace     string

	// hash chain state
	mu       sync.Mutex
	prevHash string // protected by mu

	// batch state
	batchMu  sync.Mutex
	batch    []cwltypes.InputLogEvent
	flushErr error // last flush error, reset on next success

	stopCh chan struct{}
	doneCh chan struct{}
}

// CloudWatchOptions configures a CloudWatchLogger.
type CloudWatchOptions struct {
	// LogGroupName is the CloudWatch Logs group (must already exist).
	LogGroupName string
	// LogStreamName is the per-instance log stream.
	LogStreamName string
	// InstanceID is a stable identifier for this proxy instance (used as audit chain key).
	InstanceID string
	// Workspace is the deployment workspace label (e.g., "production").
	Workspace string
	// GenesisHash is the hash chain seed for this instance.
	// Obtain it via store.DB.UpsertChainGenesis before creating the logger.
	GenesisHash string
	// FlushInterval is how often the batch is sent to CloudWatch. Default: 200ms.
	FlushInterval time.Duration
	// DB is the optional PostgreSQL store used for VerifyChain. May be nil.
	DB *store.DB
}

// NewCloudWatchLogger creates a CloudWatchLogger and starts the background flush goroutine.
// Call Close() to drain the batch and stop flushing.
func NewCloudWatchLogger(client cwClient, opts CloudWatchOptions) *CloudWatchLogger {
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 200 * time.Millisecond
	}

	l := &CloudWatchLogger{
		client:        client,
		db:            opts.DB,
		logGroupName:  opts.LogGroupName,
		logStreamName: opts.LogStreamName,
		instanceID:    opts.InstanceID,
		workspace:     opts.Workspace,
		prevHash:      opts.GenesisHash,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	go l.flushLoop(opts.FlushInterval)
	return l
}

// Emit appends an event to the hash chain and enqueues it for CloudWatch delivery.
// Also writes to PostgreSQL when a DB is configured.
// Emit is non-blocking: it returns as soon as the event is enqueued.
func (l *CloudWatchLogger) Emit(ctx context.Context, event *gateway.AuditEvent) error {
	// Assign event ID if not already set.
	if event.EventID == "" {
		event.EventID = ulid.Make().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Extend the hash chain under lock to ensure sequential ordering.
	l.mu.Lock()
	ComputeHash(event, l.prevHash)
	l.prevHash = event.Hash
	l.mu.Unlock()

	// Serialize for CloudWatch.
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshalling audit event: %w", err)
	}

	ts := event.Timestamp.UnixMilli()
	l.batchMu.Lock()
	l.batch = append(l.batch, cwltypes.InputLogEvent{
		Message:   aws.String(string(data)),
		Timestamp: aws.Int64(ts),
	})
	l.batchMu.Unlock()

	// Write to PostgreSQL synchronously so VerifyChain always has the full chain.
	if l.db != nil {
		row := eventToRow(event, l.instanceID)
		if err := l.db.InsertAuditEvent(ctx, row); err != nil {
			// Non-fatal: log and continue.
			slog.ErrorContext(ctx, "audit: failed to persist event to postgres",
				slog.String("event_id", event.EventID),
				slog.String("error", err.Error()),
			)
		}
	}

	return nil
}

// VerifyChain delegates to the store.DB.VerifyChain when a DB is configured.
// Returns an error if called without a DB.
func (l *CloudWatchLogger) VerifyChain(ctx context.Context, instanceID string) error {
	if l.db == nil {
		return errors.New("audit: VerifyChain requires a PostgreSQL store (no DB configured)")
	}
	return l.db.VerifyChain(ctx, instanceID, RowHash)
}

// Close flushes the pending batch and stops the background goroutine.
func (l *CloudWatchLogger) Close() {
	close(l.stopCh)
	<-l.doneCh
}

// flushLoop sends batched events to CloudWatch at regular intervals.
func (l *CloudWatchLogger) flushLoop(interval time.Duration) {
	defer close(l.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.flush()
		case <-l.stopCh:
			l.flush() // drain remaining events
			return
		}
	}
}

// flush sends the current batch to CloudWatch. At most 10,000 events per call.
func (l *CloudWatchLogger) flush() {
	l.batchMu.Lock()
	if len(l.batch) == 0 {
		l.batchMu.Unlock()
		return
	}
	// Drain up to 10,000 events (CloudWatch PutLogEvents limit).
	const maxBatch = 10_000
	toSend := l.batch
	if len(toSend) > maxBatch {
		toSend = toSend[:maxBatch]
		l.batch = l.batch[maxBatch:]
	} else {
		l.batch = l.batch[:0]
	}
	l.batchMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := l.client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String(l.logGroupName),
		LogStreamName: aws.String(l.logStreamName),
		LogEvents:     toSend,
	})
	if err != nil {
		// On InvalidSequenceTokenException or DataAlreadyAcceptedException the
		// SDK v2 automatically retries with the correct token, so we only log here.
		slog.Error("audit: CloudWatch PutLogEvents failed",
			slog.String("error", err.Error()),
			slog.Int("events", len(toSend)),
		)
		l.batchMu.Lock()
		// Prepend the failed events back so they are retried next tick.
		l.batch = append(toSend, l.batch...)
		l.batchMu.Unlock()
	}
}

// eventToRow converts a gateway.AuditEvent to a store.AuditRow for PostgreSQL insertion.
func eventToRow(e *gateway.AuditEvent, instanceID string) *store.AuditRow {
	return &store.AuditRow{
		EventID:           e.EventID,
		InstanceID:        instanceID,
		Timestamp:         e.Timestamp,
		RequestID:         e.RequestID,
		CallerSub:         e.CallerSubject,
		CallerType:        string(e.CallerType),
		CallerGroups:      e.CallerGroups,
		CallerSessionID:   e.CallerSessionID,
		ToolNamespaced:    e.ToolNamespaced,
		ArgumentsHash:     e.ArgumentsHash,
		CredentialRef:     e.CredentialRef,
		Decision:          string(e.Decision),
		PolicyRule:        e.PolicyRule,
		PolicyReason:      e.PolicyReason,
		PolicyEvalError:   e.PolicyEvalError,
		Workspace:         e.Workspace,
		DownstreamStatus:  e.DownstreamStatus,
		LatencyMs:         e.LatencyMs,
		DownstreamMs:      e.DownstreamMs,
		RedactionsApplied: e.RedactionsApplied,
		PrevHash:          e.PrevHash,
		Hash:              e.Hash,
	}
}

var _ gateway.AuditLogger = (*CloudWatchLogger)(nil)
