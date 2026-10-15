package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// CreateSession stores a login session; only the token's hash is kept.
func (s *Store) CreateSession(ctx context.Context, userID, tokenHash string, now time.Time, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at)
		VALUES ($1, $2, $3, $4, $3)`, tokenHash, userID, now, now.Add(ttl))
	return err
}

// SessionUser returns the user of an unexpired session, or nil.
func (s *Store) SessionUser(ctx context.Context, tokenHash string, now time.Time) (*models.User, error) {
	var u models.User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// TouchSession records use of a session, at most once a minute.
func (s *Store) TouchSession(ctx context.Context, tokenHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET last_used_at = $2
		WHERE token_hash = $1 AND last_used_at < $3`, tokenHash, now, now.Add(-time.Minute))
	return err
}

// DeleteSession revokes one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUserSessions revokes every session of a user except exceptHash.
func (s *Store) DeleteUserSessions(ctx context.Context, userID, exceptHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, exceptHash)
	return err
}

// DeleteExpiredSessions removes sessions past their expiry.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	return err
}

// ChangePassword sets a user's password hash and revokes the user's other
// sessions (all but keepHash) in one transaction.
func (s *Store) ChangePassword(ctx context.Context, userID, passwordHash, keepHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit
	res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, userID, passwordHash)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, keepHash); err != nil {
		return err
	}
	return tx.Commit()
}

// ListInterfaceNames returns the WireGuard interface of every network that
// has one; /health needs only these, not the networks' keys.
func (s *Store) ListInterfaceNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT interface_name FROM networks WHERE interface_name <> '' ORDER BY interface_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// ListSessions returns the sessions that have not expired, newest use first.
func (s *Store) ListSessions(ctx context.Context, now time.Time) ([]*models.SessionInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, u.username, s.created_at, s.last_used_at, s.expires_at, s.token_hash
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.expires_at > $1
		ORDER BY s.last_used_at DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.SessionInfo{}
	for rows.Next() {
		si := &models.SessionInfo{}
		if err := rows.Scan(&si.ID, &si.Username, &si.CreatedAt, &si.LastUsedAt, &si.ExpiresAt, &si.TokenHash); err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// DeleteSessionByID ends one session; it reports whether it existed.
func (s *Store) DeleteSessionByID(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ElevateSession marks a session as stepped up (the password was entered
// again) until the given time.
func (s *Store) ElevateSession(ctx context.Context, tokenHash string, until time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET elevated_until = $2 WHERE token_hash = $1`, tokenHash, until)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SessionElevatedUntil returns until when a session is stepped up (zero
// when it never was).
func (s *Store) SessionElevatedUntil(ctx context.Context, tokenHash string) (time.Time, error) {
	var until sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT elevated_until FROM sessions WHERE token_hash = $1`, tokenHash).Scan(&until)
	if err != nil {
		return time.Time{}, err
	}
	return until.Time, nil
}
