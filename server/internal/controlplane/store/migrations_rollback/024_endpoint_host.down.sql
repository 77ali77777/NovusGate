-- Rollback for 024_endpoint_host.sql. Run manually with psql. Configs go
-- back to the IP endpoint: devices with a domain config keep working while
-- the domain points at the server.
BEGIN;
ALTER TABLE vpn_settings DROP COLUMN IF EXISTS endpoint_host;
DELETE FROM schema_migrations WHERE version = '024_endpoint_host.sql';
COMMIT;
