-- Rollback for 021_config_routes.sql. Run manually with psql. Only the
-- record of handed-out configs goes; configs on devices are not affected.
BEGIN;
ALTER TABLE nodes DROP COLUMN IF EXISTS config_routes;
DELETE FROM schema_migrations WHERE version = '021_config_routes.sql';
COMMIT;
