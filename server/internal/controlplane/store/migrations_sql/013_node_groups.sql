-- Migration: 013_node_groups.sql
-- Purpose: node groups (P9a). VPN rules can name a group as source or
-- destination; a group named by a rule cannot be deleted (RESTRICT).
-- rollback: internal/controlplane/store/migrations_rollback/013_node_groups.down.sql
CREATE TABLE IF NOT EXISTS node_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS node_group_members (
    group_id UUID NOT NULL REFERENCES node_groups(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_node_group_members_node ON node_group_members(node_id);

ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS source_group_id UUID REFERENCES node_groups(id) ON DELETE RESTRICT;
ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS dest_group_id UUID REFERENCES node_groups(id) ON DELETE RESTRICT;
ALTER TABLE firewall_rules DROP CONSTRAINT IF EXISTS firewall_rules_source_type_check;
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_source_type_check
    CHECK (source_type IN ('any', 'network', 'node', 'custom', 'group'));
ALTER TABLE firewall_rules DROP CONSTRAINT IF EXISTS firewall_rules_dest_type_check;
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_dest_type_check
    CHECK (dest_type IN ('any', 'network', 'node', 'custom', 'group'));
