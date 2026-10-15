-- Migration: 019_server_admin.sql
-- Purpose: server administration (P10a). A session may be "stepped up" for
-- five minutes by entering the password again, which server changes need;
-- each network may hand its nodes DNS servers.
-- rollback: internal/controlplane/store/migrations_rollback/019_server_admin.down.sql
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS elevated_until TIMESTAMPTZ;
ALTER TABLE networks ADD COLUMN IF NOT EXISTS client_dns TEXT NOT NULL DEFAULT '';
