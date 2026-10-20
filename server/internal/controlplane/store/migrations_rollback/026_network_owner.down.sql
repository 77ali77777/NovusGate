-- Rollback for 026_network_owner.sql. Run manually with psql. Without
-- scope_mode an empty network_ids means every network, so a role limited
-- to its own networks would see them all: such roles lose every
-- permission first (an admin gives them new ones afterwards).
BEGIN;
UPDATE roles SET permissions = '{}'::jsonb WHERE scope_mode = 'own';
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_max_networks_check;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_scope_mode_check;
ALTER TABLE roles DROP COLUMN IF EXISTS max_networks;
ALTER TABLE roles DROP COLUMN IF EXISTS scope_mode;
DROP INDEX IF EXISTS networks_owner_idx;
ALTER TABLE networks DROP COLUMN IF EXISTS owner_user_id;
DELETE FROM schema_migrations WHERE version = '026_network_owner.sql';
COMMIT;
