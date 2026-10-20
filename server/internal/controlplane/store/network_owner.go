package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// ErrNetworkLimit: the user already has as many networks as its role allows.
var ErrNetworkLimit = errors.New("network limit reached")

// scopeOrAll is a role's scope mode, "all" when unset.
func scopeOrAll(mode string) string {
	if mode == "" {
		return "all"
	}
	return mode
}

// CreateOwnedNetwork creates a network owned by userID unless the user
// already owns max networks (ErrNetworkLimit). The user row is locked, so
// two requests at once cannot both pass the count.
func (s *Store) CreateOwnedNetwork(ctx context.Context, network *models.Network, userID string, max int) error {
	userID, err := canonicalID(userID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&locked); err != nil {
		return err
	}
	var owned int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM networks WHERE owner_user_id = $1`, userID).Scan(&owned); err != nil {
		return err
	}
	if owned >= max {
		return ErrNetworkLimit
	}
	if network.ID == "" {
		network.ID = uuid.New().String()
	}
	network.CreatedAt = time.Now()
	network.UpdatedAt = network.CreatedAt
	if network.TunnelMode == "" {
		network.TunnelMode = models.TunnelSplit
	}
	network.OwnerUserID = &userID
	if err := insertNetwork(ctx, tx, network); err != nil {
		return err
	}
	return tx.Commit()
}

// NetworksOwnedBy returns the ids of the networks a user owns.
func (s *Store) NetworksOwnedBy(ctx context.Context, userID string) ([]string, error) {
	userID, err := canonicalID(userID)
	if err != nil {
		return []string{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM networks WHERE owner_user_id = $1 ORDER BY name`, userID)
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

// SetNetworkOwner hands a network to a user (nil: no owner); an unknown
// network or user is sql.ErrNoRows.
func (s *Store) SetNetworkOwner(ctx context.Context, networkID string, userID *string) error {
	networkID, err := canonicalID(networkID)
	if err != nil {
		return err
	}
	if userID != nil {
		id, err := canonicalID(*userID)
		if err != nil {
			return err
		}
		userID = &id
	}
	res, err := s.db.ExecContext(ctx, `UPDATE networks SET owner_user_id = $2, updated_at = NOW() WHERE id = $1`, networkID, userID)
	if err != nil {
		var fk interface{ SQLState() string }
		if errors.As(err, &fk) && fk.SQLState() == "23503" {
			return sql.ErrNoRows // no such user
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
