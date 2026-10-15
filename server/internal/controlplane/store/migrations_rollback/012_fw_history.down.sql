-- Rollback for 012_fw_history.sql. Run manually with psql. The firewall
-- change history is lost; the firewall rules themselves are unchanged.
BEGIN;
DROP TABLE IF EXISTS fw_history;
DELETE FROM schema_migrations WHERE version = '012_fw_history.sql';
COMMIT;
