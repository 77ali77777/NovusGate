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
		SELECT u.id, u.username, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now).Scan(&u.ID, &u.Username, &u.CreatedAt)
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
