-- Rollback for 019_server_admin.sql. Run manually with psql. Step-ups end;
-- networks' DNS settings are removed (configs fall back to the old default).
BEGIN;
ALTER TABLE networks DROP COLUMN IF EXISTS client_dns;
ALTER TABLE sessions DROP COLUMN IF EXISTS elevated_until;
DELETE FROM schema_migrations WHERE version = '019_server_admin.sql';
COMMIT;
