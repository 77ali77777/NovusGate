-- Migration: 009_node_keys_and_audit_user.sql
-- Purpose: node private keys move out of labels into an encrypted column;
-- firewall audit entries record the panel user (P4c). Additive only. The
-- keys themselves are moved at startup by the server (MigrateNodeKeys).
-- rollback: internal/controlplane/store/migrations_rollback/009_node_keys_and_audit_user.down.sql
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS private_key_enc TEXT;
ALTER TABLE firewall_audit_log ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL;
