package store

import (
	"context"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/traffic"
)

// InsertTrafficSamples stores node counters; a sample already taken at the
// same moment is kept.
func (s *Store) InsertTrafficSamples(ctx context.Context, samples []traffic.Sample) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, smp := range samples {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_traffic_samples (node_id, sampled_at, rx_bytes, tx_bytes)
			VALUES ($1, $2, $3, $4) ON CONFLICT (node_id, sampled_at) DO NOTHING`,
			smp.NodeID, smp.At, smp.Rx, smp.Tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListTrafficSamples returns a node's samples from since on, oldest first,
// plus the last one before since so the first interval has a delta.
func (s *Store) ListTrafficSamples(ctx context.Context, nodeID string, since time.Time) ([]traffic.Sample, error) {
	rows, err := s.db.QueryContext(ctx, `
		(SELECT sampled_at, rx_bytes, tx_bytes FROM node_traffic_samples
		  WHERE node_id = $1 AND sampled_at < $2 ORDER BY sampled_at DESC LIMIT 1)
		UNION ALL
		(SELECT sampled_at, rx_bytes, tx_bytes FROM node_traffic_samples
		  WHERE node_id = $1 AND sampled_at >= $2)
		ORDER BY sampled_at`, nodeID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []traffic.Sample{}
	for rows.Next() {
		smp := traffic.Sample{NodeID: nodeID}
		if err := rows.Scan(&smp.At, &smp.Rx, &smp.Tx); err != nil {
			return nil, err
		}
		out = append(out, smp)
	}
	return out, rows.Err()
}

// DeleteTrafficSamplesBefore drops samples older than t (retention).
func (s *Store) DeleteTrafficSamplesBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM node_traffic_samples WHERE sampled_at < $1`, t)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
