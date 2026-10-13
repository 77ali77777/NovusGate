-- Migration: 006_firewall_engine.sql
-- Purpose: state owned by the nftables firewall engine (P3b). Additive only;
-- rollback: internal/controlplane/store/migrations_rollback/006_firewall_engine.down.sql

-- Host ports opened by the panel (input chain).
CREATE TABLE IF NOT EXISTS fw_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    protocol VARCHAR(3) NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port_from INT NOT NULL CHECK (port_from BETWEEN 1 AND 65535),
    port_to INT NOT NULL CHECK (port_to BETWEEN 1 AND 65535 AND port_to >= port_from),
    sources TEXT[] NOT NULL DEFAULT '{}',
    interface VARCHAR(15),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-source blocks and allows; blocks without ports go to the blocked set.
CREATE TABLE IF NOT EXISTS fw_ip_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(5) NOT NULL CHECK (action IN ('block', 'allow')),
    prefix CIDR NOT NULL,
    protocol VARCHAR(3) CHECK (protocol IN ('tcp', 'udp')),
    ports TEXT,
    expires_at TIMESTAMPTZ,
    origin VARCHAR(10) NOT NULL DEFAULT 'panel' CHECK (origin IN ('panel', 'fail2ban', 'import')),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fw_ip_rules_expires ON fw_ip_rules(expires_at);

-- Public port -> VPN node port forwards.
CREATE TABLE IF NOT EXISTS fw_forwards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    protocol VARCHAR(3) NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    public_port INT NOT NULL CHECK (public_port BETWEEN 1 AND 65535),
    target_ip INET NOT NULL,
    target_port INT NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (protocol, public_port)
);

-- Nodes allowed to reach the internet through the server (full tunnel).
CREATE TABLE IF NOT EXISTS fw_egress (
    node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Engine bookkeeping, e.g. whether iptables rules were imported.
CREATE TABLE IF NOT EXISTS fw_meta (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
