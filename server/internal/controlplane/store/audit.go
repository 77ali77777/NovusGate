package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// ListAuditLog returns up to limit audit entries before the cursor (all when
// before is nil), newest first. The cursor is the last entry shown: its time
// and, so entries with the same time are not lost at a page edge, its id
// (empty for a time-only cursor).
func (s *Store) ListAuditLog(ctx context.Context, limit int, before *time.Time, beforeID string) ([]*models.AuditEntry, error) {
	var b sql.NullTime
	if before != nil {
		b = sql.NullTime{Time: *before, Valid: true}
	}
	var id sql.NullString
	if beforeID != "" {
		id = sql.NullString{String: beforeID, Valid: true}
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.created_at, a.action, COALESCE(a.details, '{}'::jsonb)::text, COALESCE(a.user_ip, ''), COALESCE(u.username, '')
		FROM firewall_audit_log a LEFT JOIN users u ON u.id = a.user_id
		WHERE $1::timestamptz IS NULL
			OR ($3::uuid IS NULL AND a.created_at < $1)
			OR ($3::uuid IS NOT NULL AND (a.created_at, a.id) < ($1, $3::uuid))
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT $2`, b, limit, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.AuditEntry{}
	for rows.Next() {
		e := &models.AuditEntry{}
		var details string
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Action, &details, &e.UserIP, &e.Username); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(details), &e.Details); err != nil || e.Details == nil {
			e.Details = map[string]any{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditRetention is how long audit entries are kept.
const AuditRetention = 180 * 24 * time.Hour

// DeleteAuditLogBefore removes audit entries older than t.
func (s *Store) DeleteAuditLogBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM firewall_audit_log WHERE created_at < $1`, t)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
