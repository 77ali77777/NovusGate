-- Rollback for 020_tunnel_mode.sql. Run manually with psql, before starting
-- the previous control plane. Every node that uses the hub as internet exit
-- (its override, or else its network, says full) gets its fw_egress row
-- back, so full tunnel stays on for exactly the same nodes.
BEGIN;
CREATE TABLE IF NOT EXISTS fw_egress (
    node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO fw_egress (node_id)
    SELECT n.id FROM nodes n JOIN networks w ON w.id = n.network_id
    WHERE COALESCE(n.tunnel_override, w.tunnel_mode) = 'full'
    ON CONFLICT (node_id) DO NOTHING;
ALTER TABLE nodes DROP COLUMN IF EXISTS tunnel_override;
ALTER TABLE networks DROP COLUMN IF EXISTS tunnel_mode;
DELETE FROM schema_migrations WHERE version = '020_tunnel_mode.sql';
COMMIT;
