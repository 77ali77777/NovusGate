-- Migration: 022_rule_bidirectional.sql
-- Purpose: VLAN-style access (plan 2026-10-19, M2). A VPN rule is one-way
-- (its source may start connections, replies come back) or mutual (both
-- ends may start them): one rule, applied both ways. Existing rules stay
-- one-way, as they were.
-- rollback: internal/controlplane/store/migrations_rollback/022_rule_bidirectional.down.sql
ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS bidirectional BOOLEAN NOT NULL DEFAULT false;
