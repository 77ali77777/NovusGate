package store

import (
	"context"
	"time"
)

// CreateEnrollmentToken stores a one-time token that lets nodeID check in;
// only the token's hash is kept.
func (s *Store) CreateEnrollmentToken(ctx context.Context, nodeID, tokenHash string, now time.Time, ttl time.Duration) error {
	// Housekeeping: used or expired tokens older than a day are no longer
	// useful for diagnosis; a failure here only leaves old rows.
	s.db.ExecContext(ctx, `DELETE FROM enrollment_tokens
		WHERE (used_at IS NOT NULL OR expires_at <= $1) AND created_at < $2`, now, now.Add(-24*time.Hour))
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO enrollment_tokens (node_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`, nodeID, tokenHash, now, now.Add(ttl))
	return err
}

// ConsumeEnrollmentToken marks an unused, unexpired token of nodeID as used
// and reports whether there was one. One statement, so a token cannot be
// used twice by concurrent requests.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, nodeID, tokenHash string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_tokens SET used_at = $3
		WHERE node_id = $1 AND token_hash = $2 AND used_at IS NULL AND expires_at > $3`, nodeID, tokenHash, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
