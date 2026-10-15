-- Rollback for 015_limit_profiles.sql. Run manually with psql. Every limit
-- profile and its node/group bindings are removed.
BEGIN;
DROP INDEX IF EXISTS idx_nodes_limit_profile;
ALTER TABLE nodes DROP COLUMN IF EXISTS limit_profile_id;
ALTER TABLE node_groups DROP COLUMN IF EXISTS limit_profile_id;
DROP TABLE IF EXISTS limit_profiles;
DELETE FROM schema_migrations WHERE version = '015_limit_profiles.sql';
COMMIT;
