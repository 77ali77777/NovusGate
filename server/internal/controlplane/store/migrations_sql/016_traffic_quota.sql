-- Migration: 016_traffic_quota.sql
-- Purpose: monthly traffic quotas on limit profiles (P9c). The count is kept
-- incrementally in node_quota_state (traffic samples are kept for 30 days,
-- a period can be 31). Over the quota a node is blocked or throttled.
-- rollback: internal/controlplane/store/migrations_rollback/016_traffic_quota.down.sql
ALTER TABLE limit_profiles ADD COLUMN IF NOT EXISTS quota_mb INTEGER CHECK (quota_mb > 0);
ALTER TABLE limit_profiles ADD COLUMN IF NOT EXISTS quota_action TEXT NOT NULL DEFAULT 'block';
ALTER TABLE limit_profiles DROP CONSTRAINT IF EXISTS limit_profiles_quota_action_check;
ALTER TABLE limit_profiles ADD CONSTRAINT limit_profiles_quota_action_check CHECK (quota_action IN ('block', 'throttle'));
ALTER TABLE limit_profiles ADD COLUMN IF NOT EXISTS throttle_kbps INTEGER CHECK (throttle_kbps > 0);
ALTER TABLE limit_profiles ADD COLUMN IF NOT EXISTS quota_reset_day SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE limit_profiles DROP CONSTRAINT IF EXISTS limit_profiles_quota_reset_day_check;
ALTER TABLE limit_profiles ADD CONSTRAINT limit_profiles_quota_reset_day_check CHECK (quota_reset_day BETWEEN 1 AND 28);

CREATE TABLE IF NOT EXISTS node_quota_state (
    node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    used_bytes BIGINT NOT NULL DEFAULT 0,
    last_rx BIGINT NOT NULL DEFAULT 0,
    last_tx BIGINT NOT NULL DEFAULT 0,
    warned_at TIMESTAMPTZ,
    exceeded_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS quota_exceeded BOOLEAN NOT NULL DEFAULT TRUE;
