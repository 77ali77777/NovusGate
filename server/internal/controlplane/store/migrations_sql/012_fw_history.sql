-- Migration: 012_fw_history.sql
-- Purpose: firewall change history (P3c History). One row per applied
-- change holds the engine state after it; the newest 200 are kept.
-- rollback: internal/controlplane/store/migrations_rollback/012_fw_history.down.sql
CREATE TABLE IF NOT EXISTS fw_history (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    state JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fw_history_created ON fw_history(created_at DESC);
