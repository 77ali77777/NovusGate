-- Rollback for 016_traffic_quota.sql. Run manually with psql. Quota settings
-- and every node's count are removed; blocked nodes are unblocked on the
-- next firewall apply of the older binary.
BEGIN;
ALTER TABLE notification_settings DROP COLUMN IF EXISTS quota_exceeded;
DROP TABLE IF EXISTS node_quota_state;
ALTER TABLE limit_profiles DROP CONSTRAINT IF EXISTS limit_profiles_quota_reset_day_check;
ALTER TABLE limit_profiles DROP CONSTRAINT IF EXISTS limit_profiles_quota_action_check;
ALTER TABLE limit_profiles DROP COLUMN IF EXISTS quota_reset_day;
ALTER TABLE limit_profiles DROP COLUMN IF EXISTS throttle_kbps;
ALTER TABLE limit_profiles DROP COLUMN IF EXISTS quota_action;
ALTER TABLE limit_profiles DROP COLUMN IF EXISTS quota_mb;
DELETE FROM schema_migrations WHERE version = '016_traffic_quota.sql';
COMMIT;
