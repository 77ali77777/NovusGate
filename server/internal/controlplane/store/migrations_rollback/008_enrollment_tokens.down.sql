-- Rollback for 008_enrollment_tokens.sql. Run manually with psql. Unused
-- install scripts stop working; the old binary does not read this table.
BEGIN;
DROP TABLE IF EXISTS enrollment_tokens;
DELETE FROM schema_migrations WHERE version = '008_enrollment_tokens.sql';
COMMIT;
