package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/novusgate/novusgate/internal/shared/secretbox"
)

// SetKeyBox sets the master-key box node private keys are sealed with; nil
// stores them with a "plain:" prefix.
func (s *Store) SetKeyBox(b *secretbox.Box) {
	s.box = b
}

// SetNodePrivateKey stores a node's WireGuard private key, sealed.
func (s *Store) SetNodePrivateKey(ctx context.Context, nodeID, key string) error {
	sealed, err := secretbox.Seal(s.box, key)
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
	return secretbox.Open(s.box, stored.String)
}

// MigrateNodeKeys moves private keys from labels into the sealed column and,
// once a master key is set, re-seals keys stored as plain text. It is safe
// to run on every start.
func (s *Store) MigrateNodeKeys(ctx context.Context) (moved, resealed int, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, labels->>'wireguard_private_key' FROM nodes WHERE labels ? 'wireguard_private_key'`)
	if err != nil {
		return 0, 0, err
	}
	legacy := map[string]string{}
	for rows.Next() {
		var id string
		var key sql.NullString
		if err := rows.Scan(&id, &key); err != nil {
			rows.Close()
			return 0, 0, err
		}
		legacy[id] = key.String
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	for id, key := range legacy {
		sealed, err := secretbox.Seal(s.box, key)
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
	rows, err = s.db.QueryContext(ctx, `SELECT id, private_key_enc FROM nodes WHERE private_key_enc LIKE 'plain:%'`)
	if err != nil {
		return moved, 0, err
	}
	plain := map[string]string{}
	for rows.Next() {
		var id, stored string
		if err := rows.Scan(&id, &stored); err != nil {
			rows.Close()
			return moved, 0, err
		}
		plain[id] = stored
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return moved, 0, err
	}
	for id, stored := range plain {
		key, err := secretbox.Open(s.box, stored)
		if err != nil {
			return moved, resealed, err
		}
		sealed, err := secretbox.Seal(s.box, key)
		if err != nil {
			return moved, resealed, err
		}
		if _, err := s.db.ExecContext(ctx, `
			UPDATE nodes SET private_key_enc = $2 WHERE id = $1 AND private_key_enc = $3`, id, sealed, stored); err != nil {
			return moved, resealed, fmt.Errorf("reseal key of node %s: %w", id, err)
		}
		resealed++
	}
	return moved, resealed, nil
}

// RestoreNodeKeysToLabels writes every node's decrypted private key back
// into labels, for rolling back to a binary older than P4c.
func (s *Store) RestoreNodeKeysToLabels(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, private_key_enc FROM nodes WHERE private_key_enc IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	stored := map[string]string{}
	for rows.Next() {
		var id, v string
		if err := rows.Scan(&id, &v); err != nil {
			rows.Close()
			return 0, err
		}
		stored[id] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for id, v := range stored {
		key, err := secretbox.Open(s.box, v)
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
	var stored string
	err := s.db.QueryRowContext(ctx, `
		SELECT private_key_enc FROM nodes WHERE private_key_enc LIKE 'v1:%' LIMIT 1`).Scan(&stored)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := secretbox.Open(s.box, stored); err != nil {
		return fmt.Errorf("stored node keys cannot be opened (was %s changed or removed?): %w", secretbox.EnvVar, err)
	}
	return nil
}
