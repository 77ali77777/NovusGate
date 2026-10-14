-- Rollback for 010_node_traffic_samples.sql. Run manually with psql. The
-- traffic history is lost; the older binary does not read this table.
BEGIN;
DROP TABLE IF EXISTS node_traffic_samples;
DELETE FROM schema_migrations WHERE version = '010_node_traffic_samples.sql';
COMMIT;
