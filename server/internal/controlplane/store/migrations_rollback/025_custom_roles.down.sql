-- Rollback for 025_custom_roles.sql. Run manually with psql. Users with a
-- custom role become viewers (the least a built-in role allows); give them
-- their role again afterwards. The custom-role check goes first: it would
-- refuse a custom user turned viewer while role_id is still set.
BEGIN;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_custom_role_check;
UPDATE users SET role = 'viewer', role_id = NULL WHERE role = 'custom';
ALTER TABLE users DROP COLUMN IF EXISTS role_id;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'operator', 'viewer'));
DROP TABLE IF EXISTS roles;
DELETE FROM schema_migrations WHERE version = '025_custom_roles.sql';
COMMIT;
