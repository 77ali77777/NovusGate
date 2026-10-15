-- Migration: 018_set_numbers.sql
-- Purpose: stable nft set names (P9 follow-up): grp_<set_no> and
-- lim_<set_no>. Names were the place in ID order, so a new group or profile
-- renamed the others' sets and History showed changes nobody made.
-- rollback: internal/controlplane/store/migrations_rollback/018_set_numbers.down.sql
ALTER TABLE node_groups ADD COLUMN IF NOT EXISTS set_no SERIAL;
ALTER TABLE limit_profiles ADD COLUMN IF NOT EXISTS set_no SERIAL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_node_groups_set_no ON node_groups(set_no);
CREATE UNIQUE INDEX IF NOT EXISTS idx_limit_profiles_set_no ON limit_profiles(set_no);
