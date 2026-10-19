-- Migration: 023_vpn_settings.sql
-- Purpose: server-side routing (2026-10-19, P1). Every device config routes
-- one address pool; networks are made inside it, so a new network never
-- changes a config. One row.
-- rollback: internal/controlplane/store/migrations_rollback/023_vpn_settings.down.sql
CREATE TABLE IF NOT EXISTS vpn_settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    pool TEXT NOT NULL DEFAULT '10.0.0.0/8',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO vpn_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
