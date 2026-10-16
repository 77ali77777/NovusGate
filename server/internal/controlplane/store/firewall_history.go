package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// historyKeep is how many firewall history entries are kept.
const historyKeep = 200

// InsertFirewallHistory stores the entries and drops the oldest beyond
// historyKeep, all in one transaction.
func (s *Store) InsertFirewallHistory(ctx context.Context, es ...*models.FirewallHistoryEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range es {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_history (id, created_at, user_id, action, state) VALUES ($1, $2, $3, $4, $5)`,
			e.ID, e.CreatedAt, nullString(e.UserID), e.Action, string(e.State)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM fw_history WHERE id NOT IN (
			SELECT id FROM fw_history ORDER BY created_at DESC, id DESC LIMIT $1)`, historyKeep); err != nil {
		return err
	}
	return tx.Commit()
}

// HasFirewallHistory reports whether any entry exists.
func (s *Store) HasFirewallHistory(ctx context.Context) (bool, error) {
	var has bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM fw_history)`).Scan(&has)
	return has, err
}

const historyColumns = `h.id, h.created_at, COALESCE(h.user_id::text, ''), COALESCE(u.username, ''), h.action, h.state::text
	FROM fw_history h LEFT JOIN users u ON u.id = h.user_id`

func scanHistory(row interface{ Scan(...any) error }) (*models.FirewallHistoryEntry, error) {
	e := &models.FirewallHistoryEntry{}
	var state string
	if err := row.Scan(&e.ID, &e.CreatedAt, &e.UserID, &e.Username, &e.Action, &state); err != nil {
		return nil, err
	}
	e.State = []byte(state)
	return e, nil
}

// ListFirewallHistory returns up to limit entries, newest first.
func (s *Store) ListFirewallHistory(ctx context.Context, limit int) ([]*models.FirewallHistoryEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+historyColumns+` ORDER BY h.created_at DESC, h.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallHistoryEntry{}
	for rows.Next() {
		e, err := scanHistory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetFirewallHistory returns one entry, or nil when it does not exist.
func (s *Store) GetFirewallHistory(ctx context.Context, id string) (*models.FirewallHistoryEntry, error) {
	e, err := scanHistory(s.db.QueryRowContext(ctx, `SELECT `+historyColumns+` WHERE h.id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

// ReplaceFirewallState replaces every service, IP rule and forward in one
// transaction (History restore). Rows keep their IDs. Tunnel modes (who uses
// the hub as internet exit) are network and node settings and stay as they
// are: a snapshot knows neither the networks' modes nor newer nodes.
func (s *Store) ReplaceFirewallState(ctx context.Context, services []*models.FirewallService, rules []*models.FirewallIPRule,
	forwards []*models.FirewallForward) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM fw_services`, `DELETE FROM fw_ip_rules`, `DELETE FROM fw_forwards`} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	now := time.Now()
	for _, svc := range services {
		sources := svc.Sources
		if sources == nil {
			sources = []string{}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_services (id, protocol, port_from, port_to, sources, interface, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			svc.ID, svc.Protocol, svc.PortFrom, svc.PortTo, pq.Array(sources),
			nullString(svc.Interface), nullString(svc.Comment), createdOr(svc.CreatedAt, now)); err != nil {
			return err
		}
	}
	for _, r := range rules {
		origin := r.Origin
		if origin == "" {
			origin = "panel"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_ip_rules (id, action, prefix, protocol, ports, expires_at, origin, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			r.ID, r.Action, r.Prefix, nullString(r.Protocol), nullString(r.Ports), r.ExpiresAt, origin,
			nullString(r.Comment), createdOr(r.CreatedAt, now)); err != nil {
			return err
		}
	}
	for _, f := range forwards {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_forwards (id, protocol, public_port, target_ip, target_port, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			f.ID, f.Protocol, f.PublicPort, f.TargetIP, f.TargetPort, nullString(f.Comment), createdOr(f.CreatedAt, now)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func createdOr(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}
