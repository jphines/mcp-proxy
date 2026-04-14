// Package store provides PostgreSQL-backed persistence for the MCP proxy.
// It manages sessions, HITL approval records, and the tamper-evident audit log.
// The proxy degrades gracefully if PostgreSQL is unavailable: sessions are kept
// in-memory and audit logging falls back to CloudWatch-only (with an alert).
package store

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a pgxpool.Pool with convenience methods used by the proxy.
type DB struct {
	pool *pgxpool.Pool
}

// Open establishes a connection pool to PostgreSQL and runs pending migrations.
// Returns an error only for fatal connection failures; callers should log and
// degrade gracefully when this returns an error.
func Open(ctx context.Context, connStr string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	db := &DB{pool: pool}
	if err := db.runMigrations(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	slog.InfoContext(ctx, "database connected and migrations complete")
	return db, nil
}

// Close releases the connection pool.
func (db *DB) Close() {
	db.pool.Close()
}

// Pool returns the underlying connection pool for direct use by sub-packages.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// runMigrations executes all SQL migration files in order.
// Migrations are idempotent (all use IF NOT EXISTS).
func (db *DB) runMigrations(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}

	// Sort by filename to ensure stable execution order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", entry.Name(), err)
		}

		if _, err := db.pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("executing migration %s: %w", entry.Name(), err)
		}

		slog.InfoContext(ctx, "migration applied", slog.String("file", entry.Name()))
	}

	return nil
}
