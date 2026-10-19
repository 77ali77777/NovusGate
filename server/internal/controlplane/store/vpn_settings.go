package store

import (
	"context"
	"database/sql"
)

// DefaultVPNPool is the address pool device configs route (P1 of
// server-side routing) when the settings row is missing.
const DefaultVPNPool = "10.0.0.0/8"

// VPNPool returns the address pool every device config routes.
func (s *Store) VPNPool(ctx context.Context) (string, error) {
	var pool string
	err := s.db.QueryRowContext(ctx, `SELECT pool FROM vpn_settings WHERE id = 1`).Scan(&pool)
	if err == sql.ErrNoRows {
		return DefaultVPNPool, nil
	}
	return pool, err
}

// SetVPNPool stores the address pool (validated by the caller).
func (s *Store) SetVPNPool(ctx context.Context, pool string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vpn_settings (id, pool, updated_at) VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET pool = EXCLUDED.pool, updated_at = NOW()`, pool)
	return err
}
