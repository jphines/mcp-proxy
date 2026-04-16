package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/store"
)

// PostgresLogger implements gateway.AuditLogger by writing events directly to
// PostgreSQL using the same SHA-256 hash chain as CloudWatchLogger.
//
// Emit is non-blocking: events are queued into a buffered channel and flushed
// by a background goroutine. When the channel is full the event is written
// synchronously so that no events are dropped.
type PostgresLogger struct {
	db         *store.DB
	instanceID string
	workspace  string

	// hash chain state
	mu       sync.Mutex
	prevHash string

	// async write pipeline
	ch     chan *store.AuditRow
	stopCh chan struct{}
	doneCh chan struct{}
}

// PostgresOptions configures a PostgresLogger.
type PostgresOptions struct {
	// InstanceID is a stable identifier for this proxy instance.
	InstanceID string
	// Workspace is the deployment workspace label (e.g., "production").
	Workspace string
	// GenesisHash is the hash chain seed for this instance.
	// Obtain it via store.DB.UpsertChainGenesis before creating the logger.
	GenesisHash string
	// BufferSize is the number of audit rows buffered before back-pressure.
	// Default: 1024.
	BufferSize int
}

// NewPostgresLogger creates a PostgresLogger and starts its background write goroutine.
// Call Close() to drain and stop the goroutine.
func NewPostgresLogger(db *store.DB, opts PostgresOptions) *PostgresLogger {
	bufSize := opts.BufferSize
	if bufSize <= 0 {
		bufSize = 1024
	}

	l := &PostgresLogger{
		db:         db,
		instanceID: opts.InstanceID,
		workspace:  opts.Workspace,
		prevHash:   opts.GenesisHash,
		ch:         make(chan *store.AuditRow, bufSize),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	go l.writeLoop()
	return l
}

// Emit appends the event to the hash chain and queues it for PostgreSQL insertion.
// Non-blocking unless the channel is full, in which case it falls back to a
// synchronous write so no events are silently dropped.
func (l *PostgresLogger) Emit(ctx context.Context, event *gateway.AuditEvent) error {
	if event.EventID == "" {
		event.EventID = ulid.Make().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Extend the hash chain under lock to preserve ordering.
	l.mu.Lock()
	ComputeHash(event, l.prevHash)
	l.prevHash = event.Hash
	l.mu.Unlock()

	row := eventToRow(event, l.instanceID)

	// Try non-blocking enqueue first.
	select {
	case l.ch <- row:
		return nil
	default:
	}

	// Channel is full — write synchronously so the event is not dropped.
	if err := l.db.InsertAuditEvent(ctx, row); err != nil {
		slog.ErrorContext(ctx, "audit: synchronous postgres write failed",
			slog.String("event_id", event.EventID),
			slog.String("error", err.Error()),
		)
		return err
	}
	return nil
}

// VerifyChain delegates to store.DB.VerifyChain.
func (l *PostgresLogger) VerifyChain(ctx context.Context, instanceID string) error {
	return l.db.VerifyChain(ctx, instanceID, RowHash)
}

// Close drains any buffered events and stops the background goroutine.
func (l *PostgresLogger) Close() {
	close(l.stopCh)
	<-l.doneCh
}

// writeLoop drains the event channel and writes rows to PostgreSQL.
func (l *PostgresLogger) writeLoop() {
	defer close(l.doneCh)

	for {
		select {
		case row := <-l.ch:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := l.db.InsertAuditEvent(ctx, row); err != nil {
				slog.Error("audit: postgres write failed",
					slog.String("event_id", row.EventID),
					slog.String("error", err.Error()),
				)
			}
			cancel()

		case <-l.stopCh:
			// Drain remaining events before exiting.
			for {
				select {
				case row := <-l.ch:
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := l.db.InsertAuditEvent(ctx, row); err != nil {
						slog.Error("audit: postgres drain write failed",
							slog.String("event_id", row.EventID),
							slog.String("error", err.Error()),
						)
					}
					cancel()
				default:
					return
				}
			}
		}
	}
}

var _ gateway.AuditLogger = (*PostgresLogger)(nil)
