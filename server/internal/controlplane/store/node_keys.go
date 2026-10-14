package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/shared/secretbox"
)

// Node private keys are sealed with the node's ID as context, so a value
// copied to another row does not open there.

// SetKeyBox sets the master-key box node private keys are sealed with; nil
// stores them with a "plain:" prefix.
func (s *Store) SetKeyBox(b *secretbox.Box) {
	s.box = b
}

// CreateNodeWithKey creates a node together with its sealed private key in
// one INSERT, so a node never exists without the key it was created with.
func (s *Store) CreateNodeWithKey(ctx context.Context, node *models.Node, key string) error {
	prepareNode(node)
	sealed, err := secretbox.Seal(s.box, key, node.ID)
	if err != nil {
		return err
	}
	if err := s.insertNode(ctx, node, &sealed); err != nil {
		return err
	}
	node.HasConfig = true
	return nil
}

// SetNodePrivateKey stores a node's WireGuard private key, sealed.
func (s *Store) SetNodePrivateKey(ctx context.Context, nodeID, key string) error {
	sealed, err := secretbox.Seal(s.box, key, nodeID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE nodes SET private_key_enc = $2 WHERE id = $1`, nodeID, sealed)
	return err
}

// NodePrivateKey returns a node's private key, or "" when the server does
// not hold one (imported peers).
func (s *Store) NodePrivateKey(ctx context.Context, nodeID string) (string, error) {
	var stored sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT private_key_enc FROM nodes WHERE id = $1`, nodeID).Scan(&stored)
	if err == sql.ErrNoRows || (err == nil && !stored.Valid) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return secretbox.Open(s.box, stored.String, nodeID)
}

// queryPairs runs a query returning (id, value) rows.
func (s *Store) queryPairs(ctx context.Context, query string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id string
		var v sql.NullString
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v.String
	}
	return out, rows.Err()
}

// MigrateNodeKeys moves private keys from labels into the sealed column and,
// once a master key is set, re-seals keys stored as plain text or as v1
// (not yet bound to their node). It is safe
// to run on every start.
func (s *Store) MigrateNodeKeys(ctx context.Context) (moved, resealed int, err error) {
	legacy, err := s.queryPairs(ctx, `
		SELECT id, labels->>'wireguard_private_key' FROM nodes WHERE labels ? 'wireguard_private_key'`)
	if err != nil {
		return 0, 0, err
	}
	for id, key := range legacy {
		if key == "" { // nothing to keep: only drop the label
			if _, err := s.db.ExecContext(ctx, `UPDATE nodes SET labels = labels - 'wireguard_private_key' WHERE id = $1`, id); err != nil {
				return moved, 0, fmt.Errorf("drop empty key label of node %s: %w", id, err)
			}
			continue
		}
		sealed, err := secretbox.Seal(s.box, key, id)
		if err != nil {
			return moved, 0, err
		}
		// One statement: the key leaves labels exactly when the column gets it.
		// A key already in the column wins over a label (labels are not trusted).
		if _, err := s.db.ExecContext(ctx, `
			UPDATE nodes SET private_key_enc = COALESCE(private_key_enc, $2), labels = labels - 'wireguard_private_key'
			WHERE id = $1`, id, sealed); err != nil {
			return moved, 0, fmt.Errorf("move key of node %s: %w", id, err)
		}
		moved++
	}
	if s.box == nil {
		return moved, 0, nil
	}
	plain, err := s.queryPairs(ctx, `SELECT id, private_key_enc FROM nodes WHERE private_key_enc LIKE 'plain:%' OR private_key_enc LIKE 'v1:%'`)
	if err != nil {
		return moved, 0, err
	}
	for id, stored := range plain {
		key, err := secretbox.Open(s.box, stored, id)
		if err != nil {
			return moved, resealed, err
		}
		sealed, err := secretbox.Seal(s.box, key, id)
		if err != nil {
			return moved, resealed, err
		}
		res, err := s.db.ExecContext(ctx, `
			UPDATE nodes SET private_key_enc = $2 WHERE id = $1 AND private_key_enc = $3`, id, sealed, stored)
		if err != nil {
			return moved, resealed, fmt.Errorf("reseal key of node %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 1 {
			resealed++
		}
	}
	return moved, resealed, nil
}

// RestoreNodeKeysToLabels writes every node's decrypted private key back
// into labels, for rolling back to a binary older than P4c.
func (s *Store) RestoreNodeKeysToLabels(ctx context.Context) (int, error) {
	stored, err := s.queryPairs(ctx, `SELECT id, private_key_enc FROM nodes WHERE private_key_enc IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	n := 0
	for id, v := range stored {
		key, err := secretbox.Open(s.box, v, id)
		if err != nil {
			return n, fmt.Errorf("node %s: %w", id, err)
		}
		if _, err := s.db.ExecContext(ctx, `
			UPDATE nodes SET labels = COALESCE(labels, '{}'::jsonb) || jsonb_build_object('wireguard_private_key', $2::text)
			WHERE id = $1`, id, key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// CheckNodeKeys verifies that the configured master key opens the stored
// keys, so a changed or missing key stops the server at startup instead of
// failing every config download later.
func (s *Store) CheckNodeKeys(ctx context.Context) error {
	var id, stored string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, private_key_enc FROM nodes WHERE private_key_enc LIKE 'v1:%' OR private_key_enc LIKE 'v2:%' LIMIT 1`).Scan(&id, &stored)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := secretbox.Open(s.box, stored, id); err != nil {
		return fmt.Errorf("stored node keys cannot be opened (was %s changed or removed?): %w", secretbox.EnvVar, err)
	}
	return nil
}
