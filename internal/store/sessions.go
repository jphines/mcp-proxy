package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session is a persisted record of an authenticated caller session.
type Session struct {
	ID         string
	CallerSub  string
	CallerType string
	SessionID  string
	Workspace  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	Metadata   map[string]any
}

// UpsertSession inserts or updates a session record.
func (db *DB) UpsertSession(ctx context.Context, s *Session) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO sessions (id, caller_sub, caller_type, session_id, workspace,
		                      created_at, last_seen_at, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE
		  SET last_seen_at = EXCLUDED.last_seen_at,
		      expires_at   = EXCLUDED.expires_at,
		      metadata     = EXCLUDED.metadata
	`,
		s.ID, s.CallerSub, s.CallerType, s.SessionID, s.Workspace,
		s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.Metadata,
	)
	if err != nil {
		return fmt.Errorf("upserting session %s: %w", s.ID, err)
	}
	return nil
}

// GetSession retrieves a session by ID. Returns pgx.ErrNoRows if not found.
func (db *DB) GetSession(ctx context.Context, id string) (*Session, error) {
	row := db.pool.QueryRow(ctx, `
		SELECT id, caller_sub, caller_type, session_id, workspace,
		       created_at, last_seen_at, expires_at, metadata
		FROM sessions WHERE id = $1
	`, id)

	var s Session
	err := row.Scan(
		&s.ID, &s.CallerSub, &s.CallerType, &s.SessionID, &s.Workspace,
		&s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.Metadata,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteExpiredSessions removes sessions whose expiry has passed.
// Intended for a periodic cleanup goroutine.
func (db *DB) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		"DELETE FROM sessions WHERE expires_at < NOW()",
	)
	if err != nil {
		return 0, fmt.Errorf("deleting expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ensure pgx.ErrNoRows is accessible to callers doing not-found checks.
var ErrNotFound = pgx.ErrNoRows
