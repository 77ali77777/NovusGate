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

// VPNEndpointHost returns the name or address device configs reach the hub
// by ("" keeps each network's stored endpoint).
func (s *Store) VPNEndpointHost(ctx context.Context) (string, error) {
	var host string
	err := s.db.QueryRowContext(ctx, `SELECT endpoint_host FROM vpn_settings WHERE id = 1`).Scan(&host)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return host, err
}

// SetVPNEndpointHost stores the endpoint host (validated by the caller).
func (s *Store) SetVPNEndpointHost(ctx context.Context, host string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vpn_settings (id, endpoint_host, updated_at) VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET endpoint_host = EXCLUDED.endpoint_host, updated_at = NOW()`, host)
	return err
}
