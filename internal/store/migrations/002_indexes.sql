-- 002_indexes.sql
-- Additional indexes for common query patterns.

-- Fast lookup of the most recent audit event for a given instance
-- (needed for hash chain continuation on restart).
CREATE INDEX IF NOT EXISTS idx_audit_instance_last
    ON audit_events (instance_id, timestamp DESC);

-- Partial index for pending approvals (small, frequently queried).
CREATE INDEX IF NOT EXISTS idx_approval_pending
    ON approval_requests (created_at)
    WHERE status = 'pending';

-- Index to support workspace-scoped audit queries.
CREATE INDEX IF NOT EXISTS idx_audit_workspace_time
    ON audit_events (workspace, timestamp);
