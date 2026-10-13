-- Rollback for 006_firewall_engine.sql. Run manually with psql, then delete the
-- schema_migrations row so the migration can be re-applied later:
--   DELETE FROM schema_migrations WHERE version = '006_firewall_engine.sql';
-- This removes all firewall-engine state (services, IP rules, forwards, egress).
BEGIN;
DROP TABLE IF EXISTS fw_meta;
DROP TABLE IF EXISTS fw_egress;
DROP TABLE IF EXISTS fw_forwards;
DROP TABLE IF EXISTS fw_ip_rules;
DROP TABLE IF EXISTS fw_services;
DELETE FROM schema_migrations WHERE version = '006_firewall_engine.sql';
COMMIT;
