-- Rollback for 009_node_keys_and_audit_user.sql. ORDER MATTERS:
--   1. With the new binary and the same NOVUSGATE_MASTER_KEY, run
--        novusgate-server keys-to-labels
--      so every node's private key is written back into labels.
--   2. Only then run this file with psql. Dropping the column first loses
--      every node's private key (their configs must then be re-created).
BEGIN;
ALTER TABLE firewall_audit_log DROP COLUMN IF EXISTS user_id;
ALTER TABLE nodes DROP COLUMN IF EXISTS private_key_enc;
DELETE FROM schema_migrations WHERE version = '009_node_keys_and_audit_user.sql';
COMMIT;
