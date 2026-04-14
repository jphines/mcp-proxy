-- 001_initial.sql
-- Core tables for the MCP proxy.

-- sessions tracks authenticated caller sessions.
CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,          -- caller sub + session_id composite key
    caller_sub     TEXT        NOT NULL,
    caller_type    TEXT        NOT NULL,
    session_id     TEXT        NOT NULL,
    workspace      TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL,
    metadata       JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sessions_caller_sub ON sessions (caller_sub);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

-- approval_requests tracks HITL approval workflows.
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id        TEXT PRIMARY KEY,
    tool_namespaced   TEXT        NOT NULL,
    arguments_summary TEXT        NOT NULL,
    caller_sub        TEXT        NOT NULL,
    caller_type       TEXT        NOT NULL,
    policy_rule       TEXT        NOT NULL,
    policy_reason     TEXT        NOT NULL,
    channel           TEXT        NOT NULL,
    timeout_seconds   INT         NOT NULL,
    status            TEXT        NOT NULL DEFAULT 'pending',  -- pending, approved, rejected, modified, timed_out
    outcome           TEXT,
    modified_args     JSONB,
    approver_sub      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approval_requests_status    ON approval_requests (status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_caller    ON approval_requests (caller_sub);
CREATE INDEX IF NOT EXISTS idx_approval_requests_created   ON approval_requests (created_at);

-- audit_events is the tamper-evident audit log.
-- Each row chains to the previous via prev_hash / hash.
-- The chain is per-instance (instance_id), not global.
CREATE TABLE IF NOT EXISTS audit_events (
    event_id          TEXT PRIMARY KEY,       -- ULID
    instance_id       TEXT        NOT NULL,   -- proxy instance that emitted this event
    timestamp         TIMESTAMPTZ NOT NULL,
    request_id        TEXT        NOT NULL,

    caller_sub        TEXT        NOT NULL,
    caller_type       TEXT        NOT NULL,
    caller_groups     TEXT[]      NOT NULL DEFAULT '{}',
    caller_session_id TEXT        NOT NULL DEFAULT '',

    tool_namespaced   TEXT        NOT NULL,
    arguments_hash    TEXT        NOT NULL,
    credential_ref    TEXT        NOT NULL DEFAULT '',

    decision          TEXT        NOT NULL,
    policy_rule       TEXT        NOT NULL DEFAULT '',
    policy_reason     TEXT        NOT NULL DEFAULT '',
    policy_eval_error TEXT        NOT NULL DEFAULT '',

    workspace         TEXT        NOT NULL,
    downstream_status INT         NOT NULL DEFAULT 0,
    latency_ms        BIGINT      NOT NULL DEFAULT 0,
    downstream_ms     BIGINT      NOT NULL DEFAULT 0,
    redactions_applied INT        NOT NULL DEFAULT 0,

    prev_hash         TEXT        NOT NULL,
    hash              TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_instance_time ON audit_events (instance_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_caller        ON audit_events (caller_sub, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_tool          ON audit_events (tool_namespaced, timestamp);

-- audit_chain_genesis stores the per-instance genesis seed.
CREATE TABLE IF NOT EXISTS audit_chain_genesis (
    instance_id TEXT PRIMARY KEY,
    seed        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
