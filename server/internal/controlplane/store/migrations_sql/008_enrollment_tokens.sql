-- Migration: 008_enrollment_tokens.sql
-- Purpose: one-time node enrollment tokens (P4b). Only the SHA-256 is stored.
-- rollback: internal/controlplane/store/migrations_rollback/008_enrollment_tokens.down.sql
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_node ON enrollment_tokens(node_id);
