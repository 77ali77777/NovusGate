-- Migration: 010_node_traffic_samples.sql
-- Purpose: traffic history (P8). The control plane stores each node's
-- cumulative WireGuard counters every 5 minutes and keeps 30 days.
-- rollback: internal/controlplane/store/migrations_rollback/010_node_traffic_samples.down.sql
CREATE TABLE IF NOT EXISTS node_traffic_samples (
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    sampled_at TIMESTAMPTZ NOT NULL,
    rx_bytes BIGINT NOT NULL,
    tx_bytes BIGINT NOT NULL,
    PRIMARY KEY (node_id, sampled_at)
);
CREATE INDEX IF NOT EXISTS idx_node_traffic_samples_time ON node_traffic_samples(sampled_at);
