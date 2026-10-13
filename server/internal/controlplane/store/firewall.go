package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// ListFirewallServices returns the panel-opened host ports, oldest first.
func (s *Store) ListFirewallServices(ctx context.Context) ([]*models.FirewallService, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, protocol, port_from, port_to, sources, COALESCE(interface, ''), COALESCE(comment, ''), created_at
		FROM fw_services ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallService{}
	for rows.Next() {
		svc := &models.FirewallService{}
		if err := rows.Scan(&svc.ID, &svc.Protocol, &svc.PortFrom, &svc.PortTo, pq.Array(&svc.Sources),
			&svc.Interface, &svc.Comment, &svc.CreatedAt); err != nil {
			return nil, err
		}
		if svc.Sources == nil {
			svc.Sources = []string{}
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

// CreateFirewallService stores a service; an empty ID gets a new UUID.
func (s *Store) CreateFirewallService(ctx context.Context, svc *models.FirewallService) error {
	if svc.ID == "" {
		svc.ID = uuid.New().String()
	}
	if svc.Sources == nil {
		svc.Sources = []string{}
	}
	svc.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_services (id, protocol, port_from, port_to, sources, interface, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		svc.ID, svc.Protocol, svc.PortFrom, svc.PortTo, pq.Array(svc.Sources),
		nullString(svc.Interface), nullString(svc.Comment), svc.CreatedAt)
	return err
}

// DeleteFirewallService removes a service; a missing ID is not an error.
func (s *Store) DeleteFirewallService(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_services WHERE id = $1`, id)
	return err
}

// ListFirewallIPRules returns all blocks and allows, oldest first.
func (s *Store) ListFirewallIPRules(ctx context.Context) ([]*models.FirewallIPRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, action, prefix::text, COALESCE(protocol, ''), COALESCE(ports, ''), expires_at, origin, COALESCE(comment, ''), created_at
		FROM fw_ip_rules ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallIPRule{}
	for rows.Next() {
		r := &models.FirewallIPRule{}
		var expires sql.NullTime
		if err := rows.Scan(&r.ID, &r.Action, &r.Prefix, &r.Protocol, &r.Ports, &expires, &r.Origin, &r.Comment, &r.CreatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateFirewallIPRule stores a block or allow; an empty ID gets a new UUID.
func (s *Store) CreateFirewallIPRule(ctx context.Context, r *models.FirewallIPRule) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	if r.Origin == "" {
		r.Origin = "panel"
	}
	r.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_ip_rules (id, action, prefix, protocol, ports, expires_at, origin, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.ID, r.Action, r.Prefix, nullString(r.Protocol), nullString(r.Ports), r.ExpiresAt, r.Origin, nullString(r.Comment), r.CreatedAt)
	return err
}

// DeleteFirewallIPRule removes a block or allow; a missing ID is not an error.
func (s *Store) DeleteFirewallIPRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_ip_rules WHERE id = $1`, id)
	return err
}

// ListFirewallForwards returns all port forwards, oldest first.
func (s *Store) ListFirewallForwards(ctx context.Context) ([]*models.FirewallForward, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, protocol, public_port, host(target_ip), target_port, COALESCE(comment, ''), created_at
		FROM fw_forwards ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallForward{}
	for rows.Next() {
		f := &models.FirewallForward{}
		if err := rows.Scan(&f.ID, &f.Protocol, &f.PublicPort, &f.TargetIP, &f.TargetPort, &f.Comment, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFirewallForward stores a forward; an empty ID gets a new UUID.
func (s *Store) CreateFirewallForward(ctx context.Context, f *models.FirewallForward) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	f.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_forwards (id, protocol, public_port, target_ip, target_port, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		f.ID, f.Protocol, f.PublicPort, f.TargetIP, f.TargetPort, nullString(f.Comment), f.CreatedAt)
	return err
}

// DeleteFirewallForward removes a forward; a missing ID is not an error.
func (s *Store) DeleteFirewallForward(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_forwards WHERE id = $1`, id)
	return err
}

// ListEgressNodeIDs returns the nodes allowed to use the server as internet exit.
func (s *Store) ListEgressNodeIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM fw_egress ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetNodeEgress allows or forbids a node to reach the internet through the server.
func (s *Store) SetNodeEgress(ctx context.Context, nodeID string, enabled bool) error {
	if enabled {
		_, err := s.db.ExecContext(ctx, `INSERT INTO fw_egress (node_id) VALUES ($1) ON CONFLICT (node_id) DO NOTHING`, nodeID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_egress WHERE node_id = $1`, nodeID)
	return err
}

// ResetFirewallHostRules removes every service and IP rule in one transaction
// (the legacy "reset firewall" action); forwards and egress are kept.
func (s *Store) ResetFirewallHostRules(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM fw_services`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fw_ip_rules`); err != nil {
		return err
	}
	return tx.Commit()
}

// GetFirewallMeta reads an engine bookkeeping value.
func (s *Store) GetFirewallMeta(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM fw_meta WHERE key = $1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get firewall meta %s: %w", key, err)
	}
	return value, true, nil
}

// SetFirewallMeta writes an engine bookkeeping value.
func (s *Store) SetFirewallMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_meta (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, key, value)
	return err
}

// ImportFirewallRules stores imported services and IP rules and records the
// import marker in one transaction, so a failed import can simply be retried.
func (s *Store) ImportFirewallRules(ctx context.Context, services []*models.FirewallService, rules []*models.FirewallIPRule, metaKey, metaValue string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	for _, svc := range services {
		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}
		if svc.Sources == nil {
			svc.Sources = []string{}
		}
		svc.CreatedAt = now
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_services (id, protocol, port_from, port_to, sources, interface, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			svc.ID, svc.Protocol, svc.PortFrom, svc.PortTo, pq.Array(svc.Sources),
			nullString(svc.Interface), nullString(svc.Comment), svc.CreatedAt); err != nil {
			return fmt.Errorf("import service %d/%s: %w", svc.PortFrom, svc.Protocol, err)
		}
	}
	for _, r := range rules {
		if r.ID == "" {
			r.ID = uuid.New().String()
		}
		if r.Origin == "" {
			r.Origin = "import"
		}
		r.CreatedAt = now
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_ip_rules (id, action, prefix, protocol, ports, expires_at, origin, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			r.ID, r.Action, r.Prefix, nullString(r.Protocol), nullString(r.Ports), r.ExpiresAt, r.Origin, nullString(r.Comment), r.CreatedAt); err != nil {
			return fmt.Errorf("import IP rule %s: %w", r.Prefix, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO fw_meta (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, metaKey, metaValue); err != nil {
		return err
	}
	return tx.Commit()
}
