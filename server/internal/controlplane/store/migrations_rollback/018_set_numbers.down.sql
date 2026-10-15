-- Rollback for 018_set_numbers.sql. Run manually with psql. Set names go
-- back to the place in ID order on the older binary.
BEGIN;
DROP INDEX IF EXISTS idx_limit_profiles_set_no;
DROP INDEX IF EXISTS idx_node_groups_set_no;
ALTER TABLE limit_profiles DROP COLUMN IF EXISTS set_no;
ALTER TABLE node_groups DROP COLUMN IF EXISTS set_no;
DELETE FROM schema_migrations WHERE version = '018_set_numbers.sql';
COMMIT;
