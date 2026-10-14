-- Rollback for 009_node_keys_and_audit_user.sql. ORDER MATTERS:
--   1. Stop the control plane (it re-applies 009 and moves keys out of
--      labels again if it restarts after this file ran):
--        docker compose stop control-plane
--   2. With the new image and the same MASTER_KEY, write the keys back:
--        docker compose run --rm control-plane keys-to-labels
--   3. Run this file with psql, then start the old image.
-- The guard below refuses to run while any key exists only in the column.
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM nodes
               WHERE private_key_enc IS NOT NULL
                 AND NOT (COALESCE(labels, '{}'::jsonb) ? 'wireguard_private_key')) THEN
        RAISE EXCEPTION 'node private keys exist only in nodes.private_key_enc: run "novusgate-server keys-to-labels" first';
    END IF;
END $$;
ALTER TABLE firewall_audit_log DROP COLUMN IF EXISTS user_id;
ALTER TABLE nodes DROP COLUMN IF EXISTS private_key_enc;
DELETE FROM schema_migrations WHERE version = '009_node_keys_and_audit_user.sql';
COMMIT;
