-- Migration: 020_tunnel_mode.sql
-- Purpose: full tunnel per network. A network's nodes route the VPN
-- networks through the hub (split) or all IPv4 traffic (full, the hub is
-- their internet exit); one node may override its network. The nodes that
-- use the hub as internet exit now follow from these two columns, so the
-- per-node fw_egress rows become 'full' overrides and the table goes.
-- rollback: internal/controlplane/store/migrations_rollback/020_tunnel_mode.down.sql
ALTER TABLE networks ADD COLUMN IF NOT EXISTS tunnel_mode TEXT NOT NULL DEFAULT 'split'
    CHECK (tunnel_mode IN ('split', 'full'));
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS tunnel_override TEXT
    CHECK (tunnel_override IN ('split', 'full'));
-- Safe to run again (the schema_migrations row is written separately):
-- without fw_egress there is nothing left to convert.
DO $$
BEGIN
    IF to_regclass('fw_egress') IS NOT NULL THEN
        UPDATE nodes SET tunnel_override = 'full' WHERE id IN (SELECT node_id FROM fw_egress);
    END IF;
END $$;
DROP TABLE IF EXISTS fw_egress;
