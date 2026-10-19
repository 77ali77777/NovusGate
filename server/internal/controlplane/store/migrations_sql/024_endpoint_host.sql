-- Migration: 024_endpoint_host.sql
-- Purpose: server-side routing (2026-10-19, P2). Device configs may name the
-- hub by a domain; a new server IP then changes only a DNS record.
-- '' keeps each network's stored endpoint (WG_SERVER_ENDPOINT).
-- rollback: internal/controlplane/store/migrations_rollback/024_endpoint_host.down.sql
ALTER TABLE vpn_settings ADD COLUMN IF NOT EXISTS endpoint_host TEXT NOT NULL DEFAULT '';
