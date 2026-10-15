-- Migration: 017_quota_period_end.sql
-- Purpose: a quota period's end is fixed when it starts (P9c review): a reset
-- day or time zone changed mid-period applies from the next period instead
-- of wiping the count. Existing rows end one month after their start.
-- rollback: internal/controlplane/store/migrations_rollback/017_quota_period_end.down.sql
ALTER TABLE node_quota_state ADD COLUMN IF NOT EXISTS period_end TIMESTAMPTZ;
UPDATE node_quota_state SET period_end = period_start + INTERVAL '1 month' WHERE period_end IS NULL;
ALTER TABLE node_quota_state ALTER COLUMN period_end SET NOT NULL;
