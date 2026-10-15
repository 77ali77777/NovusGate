-- Migration: 015_limit_profiles.sql
-- Purpose: limit profiles (P9b): per-node speed, connection and time limits,
-- bound to nodes directly or through groups (a node's own profile wins).
-- A profile still bound to a node or group cannot be deleted (RESTRICT).
-- rollback: internal/controlplane/store/migrations_rollback/015_limit_profiles.down.sql
CREATE TABLE IF NOT EXISTS limit_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    down_kbps INTEGER CHECK (down_kbps > 0),
    up_kbps INTEGER CHECK (up_kbps > 0),
    max_connections INTEGER CHECK (max_connections > 0),
    schedule JSONB NOT NULL DEFAULT '[]',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS limit_profile_id UUID REFERENCES limit_profiles(id) ON DELETE RESTRICT;
ALTER TABLE node_groups ADD COLUMN IF NOT EXISTS limit_profile_id UUID REFERENCES limit_profiles(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_nodes_limit_profile ON nodes(limit_profile_id) WHERE limit_profile_id IS NOT NULL;
