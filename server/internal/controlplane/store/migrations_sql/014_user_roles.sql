-- Migration: 014_user_roles.sql
-- Purpose: panel roles (P9a). Existing users keep full rights (admin).
-- rollback: internal/controlplane/store/migrations_rollback/014_user_roles.down.sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'operator', 'viewer'));
