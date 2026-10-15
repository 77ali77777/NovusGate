-- Rollback for 014_user_roles.sql. Run manually with psql. Every user gets
-- full rights again (the older binary has no roles).
BEGIN;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users DROP COLUMN IF EXISTS role;
DELETE FROM schema_migrations WHERE version = '014_user_roles.sql';
COMMIT;
