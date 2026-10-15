-- Rollback for 013_node_groups.sql. Run manually with psql.
-- VPN rules that name a group are DELETED (the older schema cannot hold
-- them); the groups and their members are lost.
BEGIN;
DELETE FROM firewall_rules WHERE source_type = 'group' OR dest_type = 'group';
ALTER TABLE firewall_rules DROP CONSTRAINT IF EXISTS firewall_rules_source_type_check;
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_source_type_check
    CHECK (source_type IN ('any', 'network', 'node', 'custom'));
ALTER TABLE firewall_rules DROP CONSTRAINT IF EXISTS firewall_rules_dest_type_check;
ALTER TABLE firewall_rules ADD CONSTRAINT firewall_rules_dest_type_check
    CHECK (dest_type IN ('any', 'network', 'node', 'custom'));
ALTER TABLE firewall_rules DROP COLUMN IF EXISTS source_group_id;
ALTER TABLE firewall_rules DROP COLUMN IF EXISTS dest_group_id;
DROP TABLE IF EXISTS node_group_members;
DROP TABLE IF EXISTS node_groups;
DELETE FROM schema_migrations WHERE version = '013_node_groups.sql';
COMMIT;
