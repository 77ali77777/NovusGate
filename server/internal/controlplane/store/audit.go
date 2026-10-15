package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// ListAuditLog returns up to limit audit entries older than before (all
// when before is nil), newest first.
func (s *Store) ListAuditLog(ctx context.Context, limit int, before *time.Time) ([]*models.AuditEntry, error) {
	var b sql.NullTime
	if before != nil {
		b = sql.NullTime{Time: *before, Valid: true}
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.created_at, a.action, COALESCE(a.details, '{}'::jsonb)::text, COALESCE(a.user_ip, ''), COALESCE(u.username, '')
		FROM firewall_audit_log a LEFT JOIN users u ON u.id = a.user_id
		WHERE $1::timestamptz IS NULL OR a.created_at < $1
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT $2`, b, limit)
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
