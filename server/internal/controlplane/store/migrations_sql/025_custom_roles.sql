-- Migration: 025_custom_roles.sql
-- Purpose: custom panel roles (2026-10-20). An admin defines which sections a
-- role sees or changes (permissions: section -> none | view | edit) and,
-- optionally, the networks it is limited to (network_ids; empty: all). A
-- user has a built-in role (admin, operator, viewer) or role = 'custom'
-- with role_id. Existing users keep their roles.
-- rollback: internal/controlplane/store/migrations_rollback/025_custom_roles.down.sql
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_ids UUID[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id) ON DELETE RESTRICT;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'operator', 'viewer', 'custom'));
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_custom_role_check;
ALTER TABLE users ADD CONSTRAINT users_custom_role_check CHECK ((role = 'custom') = (role_id IS NOT NULL));
