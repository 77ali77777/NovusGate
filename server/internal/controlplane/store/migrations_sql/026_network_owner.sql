-- Migration: 026_network_owner.sql
-- Purpose: own networks (2026-10-20). A network remembers who created it;
-- a custom role may be limited to the networks its user created
-- (scope_mode 'own'), each user up to max_networks. 'listed' is the role
-- limited to network_ids, 'all' every network.
-- rollback: internal/controlplane/store/migrations_rollback/026_network_owner.down.sql
ALTER TABLE networks ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS networks_owner_idx ON networks (owner_user_id);
ALTER TABLE roles ADD COLUMN IF NOT EXISTS scope_mode TEXT NOT NULL DEFAULT 'all';
ALTER TABLE roles ADD COLUMN IF NOT EXISTS max_networks INTEGER NOT NULL DEFAULT 0;
UPDATE roles SET scope_mode = 'listed' WHERE scope_mode = 'all' AND cardinality(network_ids) > 0;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_scope_mode_check;
ALTER TABLE roles ADD CONSTRAINT roles_scope_mode_check CHECK (scope_mode IN ('all', 'listed', 'own'));
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_max_networks_check;
ALTER TABLE roles ADD CONSTRAINT roles_max_networks_check CHECK (max_networks BETWEEN 0 AND 1000);
