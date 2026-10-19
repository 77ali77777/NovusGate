-- Migration: 021_config_routes.sql
-- Purpose: VLAN-style access (plan 2026-10-19, M1). A device's config now
-- routes every VPN network (the hub's firewall alone decides who reaches
-- whom). config_routes keeps the AllowedIPs of the config last handed out
-- for the node, so the panel can say when it no longer matches (a new
-- network, a tunnel change, or a config from before this version: '').
-- rollback: internal/controlplane/store/migrations_rollback/021_config_routes.down.sql
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS config_routes TEXT NOT NULL DEFAULT '';
