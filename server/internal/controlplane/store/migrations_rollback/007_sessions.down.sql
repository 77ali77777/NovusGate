-- Rollback for 007_sessions.sql. Run manually with psql. Every logged-in
-- panel user is logged out; the old binary does not read this table.
BEGIN;
DROP TABLE IF EXISTS sessions;
DELETE FROM schema_migrations WHERE version = '007_sessions.sql';
COMMIT;
