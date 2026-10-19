-- Rollback for 022_rule_bidirectional.sql. Run manually with psql. Mutual
-- rules become one-way (their source side only): write the reverse rule
-- first where both sides must keep starting connections.
BEGIN;
ALTER TABLE firewall_rules DROP COLUMN IF EXISTS bidirectional;
DELETE FROM schema_migrations WHERE version = '022_rule_bidirectional.sql';
COMMIT;
