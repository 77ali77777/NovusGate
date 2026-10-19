-- Rollback for 023_vpn_settings.sql. Run manually with psql. Configs go
-- back to naming each network: devices must download theirs once more.
BEGIN;
DROP TABLE IF EXISTS vpn_settings;
DELETE FROM schema_migrations WHERE version = '023_vpn_settings.sql';
COMMIT;
