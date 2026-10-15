-- Rollback for 017_quota_period_end.sql. Run manually with psql.
BEGIN;
ALTER TABLE node_quota_state DROP COLUMN IF EXISTS period_end;
DELETE FROM schema_migrations WHERE version = '017_quota_period_end.sql';
COMMIT;
