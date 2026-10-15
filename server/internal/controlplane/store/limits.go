package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

var (
	// ErrLimitNameTaken: another limit profile has this name.
	ErrLimitNameTaken = errors.New("a limit profile with this name exists")
	// ErrLimitInUse: a node or group is bound to the profile.
	ErrLimitInUse = errors.New("the limit profile is bound to a node or group")
	// ErrLimitMemberNotFound: a node or group to bind does not exist.
	ErrLimitMemberNotFound = errors.New("node or group not found")
)

func limitError(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505": // unique_violation
			return ErrLimitNameTaken
		case "23503": // foreign_key_violation (a node or group is bound)
			return ErrLimitInUse
		}
	}
	return err
}

func scheduleJSON(windows []models.ScheduleWindow) ([]byte, error) {
	if windows == nil {
		windows = []models.ScheduleWindow{}
	}
	return json.Marshal(windows)
}

// CreateLimitProfile stores a profile without bindings.
func (s *Store) CreateLimitProfile(ctx context.Context, p *models.LimitProfile) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	p.CreatedAt = time.Now()
	sched, err := scheduleJSON(p.Schedule)
	if err != nil {
		return err
	}
	quotaDefaults(p)
	_, err = s.db.ExecContext(ctx, `INSERT INTO limit_profiles
		(id, name, down_kbps, up_kbps, max_connections, schedule, timezone, created_at,
		 quota_mb, quota_action, throttle_kbps, quota_reset_day)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		p.ID, p.Name, p.DownKbps, p.UpKbps, p.MaxConnections, sched, p.Timezone, p.CreatedAt,
		p.QuotaMB, p.QuotaAction, p.ThrottleKbps, p.QuotaResetDay)
	return limitError(err)
}

// UpdateLimitProfile replaces a profile's name, limits and schedule; its
// bindings are unchanged.
func (s *Store) UpdateLimitProfile(ctx context.Context, p *models.LimitProfile) error {
	sched, err := scheduleJSON(p.Schedule)
	if err != nil {
		return err
	}
	quotaDefaults(p)
	res, err := s.db.ExecContext(ctx, `UPDATE limit_profiles SET name = $2, down_kbps = $3, up_kbps = $4,
		max_connections = $5, schedule = $6, timezone = $7,
		quota_mb = $8, quota_action = $9, throttle_kbps = $10, quota_reset_day = $11 WHERE id = $1`,
		p.ID, p.Name, p.DownKbps, p.UpKbps, p.MaxConnections, sched, p.Timezone,
		p.QuotaMB, p.QuotaAction, p.ThrottleKbps, p.QuotaResetDay)
	if err != nil {
		return limitError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteLimitProfile removes a profile; ErrLimitInUse while bound.
func (s *Store) DeleteLimitProfile(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM limit_profiles WHERE id = $1`, id)
	if err != nil {
		return limitError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetLimitProfileBindings makes nodeIDs and groupIDs exactly the nodes and
// groups bound to the profile, in one transaction. A node or group bound to
// another profile moves to this one; an unknown id fails the whole change.
func (s *Store) SetLimitProfileBindings(ctx context.Context, profileID string, nodeIDs, groupIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Locking the profile row serialises concurrent bindings of it, so the
	// last one replaces the others instead of merging with them.
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM limit_profiles WHERE id = $1 FOR UPDATE`, profileID).Scan(&locked); err != nil {
		return err // sql.ErrNoRows for an unknown profile
	}
	for _, t := range []struct {
		table string
		ids   []string
	}{{"nodes", nodeIDs}, {"node_groups", groupIDs}} {
		// The table names are constants, never input.
		if _, err := tx.ExecContext(ctx, `UPDATE `+t.table+` SET limit_profile_id = NULL WHERE limit_profile_id = $1`, profileID); err != nil {
			return err
		}
		for _, id := range t.ids {
			res, err := tx.ExecContext(ctx, `UPDATE `+t.table+` SET limit_profile_id = $1 WHERE id = $2`, profileID, id)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return fmt.Errorf("%s %s: %w", t.table, id, ErrLimitMemberNotFound)
			}
		}
	}
	return tx.Commit()
}

// ListLimitProfiles returns every profile with its bindings, by name.
func (s *Store) ListLimitProfiles(ctx context.Context) ([]models.LimitProfile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.name, p.down_kbps, p.up_kbps, p.max_connections,
		p.schedule, p.timezone, p.created_at, p.quota_mb, p.quota_action, p.throttle_kbps, p.quota_reset_day,
		COALESCE((SELECT array_agg(n.id::text ORDER BY n.id) FROM nodes n WHERE n.limit_profile_id = p.id), '{}'),
		COALESCE((SELECT array_agg(g.id::text ORDER BY g.id) FROM node_groups g WHERE g.limit_profile_id = p.id), '{}')
		FROM limit_profiles p ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.LimitProfile{}
	for rows.Next() {
		var p models.LimitProfile
		var down, up, conns sql.NullInt64
		var sched []byte
		var nodeIDs, groupIDs pq.StringArray
		var quotaMB, throttle sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Name, &down, &up, &conns, &sched, &p.Timezone, &p.CreatedAt,
			&quotaMB, &p.QuotaAction, &throttle, &p.QuotaResetDay, &nodeIDs, &groupIDs); err != nil {
			return nil, err
		}
		p.DownKbps, p.UpKbps, p.MaxConnections = intPtr(down), intPtr(up), intPtr(conns)
		p.QuotaMB, p.ThrottleKbps = intPtr(quotaMB), intPtr(throttle)
		if err := json.Unmarshal(sched, &p.Schedule); err != nil {
			return nil, fmt.Errorf("limit profile %s: schedule: %w", p.ID, err)
		}
		p.NodeIDs, p.GroupIDs = []string(nodeIDs), []string(groupIDs)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListNodeLimits returns the profile in force for every limited node: its
// own, or else that of its first group by name that has one.
func (s *Store) ListNodeLimits(ctx context.Context) ([]models.NodeLimit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT n.id, host(n.virtual_ip),
		COALESCE(n.limit_profile_id::text, g.limit_profile_id::text), COALESCE(g.id::text, '')
		FROM nodes n
		LEFT JOIN LATERAL (
			SELECT gg.id, gg.limit_profile_id FROM node_group_members m
			JOIN node_groups gg ON gg.id = m.group_id
			WHERE m.node_id = n.id AND gg.limit_profile_id IS NOT NULL
			ORDER BY gg.name LIMIT 1
		) g ON n.limit_profile_id IS NULL
		WHERE n.limit_profile_id IS NOT NULL OR g.id IS NOT NULL
		ORDER BY n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NodeLimit{}
	for rows.Next() {
		var l models.NodeLimit
		if err := rows.Scan(&l.NodeID, &l.VirtualIP, &l.ProfileID, &l.GroupID); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func intPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	i := int(v.Int64)
	return &i
}

// quotaDefaults fills the quota settings a request may leave out.
func quotaDefaults(p *models.LimitProfile) {
	if p.QuotaAction == "" {
		p.QuotaAction = "block"
	}
	if p.QuotaResetDay == 0 {
		p.QuotaResetDay = 1
	}
}

// ListQuotaStates returns every node's quota count (P9c).
func (s *Store) ListQuotaStates(ctx context.Context) ([]models.NodeQuotaState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, period_start, used_bytes, last_rx, last_tx,
		warned_at, exceeded_at FROM node_quota_state ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NodeQuotaState{}
	for rows.Next() {
		var st models.NodeQuotaState
		var warned, exceeded sql.NullTime
		if err := rows.Scan(&st.NodeID, &st.PeriodStart, &st.UsedBytes, &st.LastRx, &st.LastTx, &warned, &exceeded); err != nil {
			return nil, err
		}
		if warned.Valid {
			st.WarnedAt = &warned.Time
		}
		if exceeded.Valid {
			st.ExceededAt = &exceeded.Time
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveQuotaState stores a node's count, replacing the previous one.
func (s *Store) SaveQuotaState(ctx context.Context, st models.NodeQuotaState) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO node_quota_state
		(node_id, period_start, used_bytes, last_rx, last_tx, warned_at, exceeded_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (node_id) DO UPDATE SET period_start = EXCLUDED.period_start,
			used_bytes = EXCLUDED.used_bytes, last_rx = EXCLUDED.last_rx, last_tx = EXCLUDED.last_tx,
			warned_at = EXCLUDED.warned_at, exceeded_at = EXCLUDED.exceeded_at, updated_at = NOW()`,
		st.NodeID, st.PeriodStart, st.UsedBytes, st.LastRx, st.LastTx, st.WarnedAt, st.ExceededAt)
	return err
}

// ResetQuotaState starts a node's count of the current period again and
// lifts its quota ("reset now" in the panel); sql.ErrNoRows without a count.
func (s *Store) ResetQuotaState(ctx context.Context, nodeID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE node_quota_state SET used_bytes = 0, warned_at = NULL,
		exceeded_at = NULL, updated_at = NOW() WHERE node_id = $1`, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
