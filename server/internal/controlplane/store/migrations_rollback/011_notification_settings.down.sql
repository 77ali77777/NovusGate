-- Rollback for 011_notification_settings.sql. Run manually with psql. The
-- notification settings and the stored bot token are lost.
BEGIN;
DROP TABLE IF EXISTS notification_settings;
DELETE FROM schema_migrations WHERE version = '011_notification_settings.sql';
COMMIT;
