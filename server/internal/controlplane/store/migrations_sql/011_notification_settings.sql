-- Migration: 011_notification_settings.sql
-- Purpose: Telegram notification settings (P8). One row; the bot token is
-- sealed with NOVUSGATE_MASTER_KEY like node private keys.
-- rollback: internal/controlplane/store/migrations_rollback/011_notification_settings.down.sql
CREATE TABLE IF NOT EXISTS notification_settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    chat_id TEXT NOT NULL DEFAULT '',
    bot_token_enc TEXT,
    node_offline BOOLEAN NOT NULL DEFAULT TRUE,
    node_expired BOOLEAN NOT NULL DEFAULT TRUE,
    fail2ban_ban BOOLEAN NOT NULL DEFAULT TRUE,
    firewall_change BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
