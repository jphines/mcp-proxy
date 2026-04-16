-- 003_credentials.sql: credential storage table for the PostgreSQL-backed CredentialStore.
-- Credentials are stored as AES-256-GCM ciphertext in the payload column.

CREATE TABLE IF NOT EXISTS credentials (
    scope_level TEXT        NOT NULL,
    owner_id    TEXT        NOT NULL DEFAULT '',
    service_id  TEXT        NOT NULL,
    payload     BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    PRIMARY KEY (scope_level, owner_id, service_id)
);

CREATE INDEX IF NOT EXISTS idx_credentials_owner ON credentials (owner_id);
