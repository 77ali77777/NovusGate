package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

var (
	// ErrGroupNameTaken: another group has this name.
	ErrGroupNameTaken = errors.New("a group with this name exists")
	// ErrGroupInUse: a VPN rule names the group, so it cannot be deleted.
	ErrGroupInUse = errors.New("the group is used by a VPN rule")
)

func groupError(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505": // unique_violation
			return ErrGroupNameTaken
		case "23503": // foreign_key_violation (a rule references the group)
			return ErrGroupInUse
		}
	}
	return err
}

// CreateNodeGroup stores a group without members.
func (s *Store) CreateNodeGroup(ctx context.Context, g *models.NodeGroup) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	g.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO node_groups (id, name, description, created_at) VALUES ($1, $2, $3, $4)`,
		g.ID, g.Name, g.Description, g.CreatedAt)
	return groupError(err)
}

// UpdateNodeGroup renames a group or changes its description.
func (s *Store) UpdateNodeGroup(ctx context.Context, g *models.NodeGroup) error {
	res, err := s.db.ExecContext(ctx, `UPDATE node_groups SET name = $2, description = $3 WHERE id = $1`, g.ID, g.Name, g.Description)
	if err != nil {
		return groupError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteNodeGroup removes a group; ErrGroupInUse while a rule names it.
func (s *Store) DeleteNodeGroup(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM node_groups WHERE id = $1`, id)
	if err != nil {
		return groupError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetNodeGroupMembers replaces a group's members in one transaction; an
// unknown node fails the whole change.
func (s *Store) SetNodeGroupMembers(ctx context.Context, groupID string, nodeIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_group_members WHERE group_id = $1`, groupID); err != nil {
		return err
	}
	for _, id := range nodeIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_group_members (group_id, node_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			groupID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListNodeGroups returns every group with its members, by name.
func (s *Store) ListNodeGroups(ctx context.Context) ([]*models.NodeGroup, error) {
	return s.queryGroups(ctx, ``)
}

// GetNodeGroup returns one group with its members, or nil.
func (s *Store) GetNodeGroup(ctx context.Context, id string) (*models.NodeGroup, error) {
	groups, err := s.queryGroups(ctx, `WHERE g.id = $1`, id)
	if err != nil || len(groups) == 0 {
		return nil, err
	}
	return groups[0], nil
}

func (s *Store) queryGroups(ctx context.Context, where string, args ...any) ([]*models.NodeGroup, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, g.description, g.created_at,
			COALESCE(n.id::text, ''), COALESCE(n.name, ''), COALESCE(host(n.virtual_ip), ''), COALESCE(n.network_id::text, '')
		FROM node_groups g
		LEFT JOIN node_group_members m ON m.group_id = g.id
		LEFT JOIN nodes n ON n.id = m.node_id
		`+where+`
		ORDER BY g.name, n.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.NodeGroup{}
	byID := map[string]*models.NodeGroup{}
	for rows.Next() {
		var g models.NodeGroup
		var m models.NodeGroupMember
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &m.NodeID, &m.Name, &m.VirtualIP, &m.NetworkID); err != nil {
			return nil, err
		}
		cur := byID[g.ID]
		if cur == nil {
			g.Members = []models.NodeGroupMember{}
			cur = &g
			byID[g.ID] = cur
			out = append(out, cur)
		}
		if m.NodeID != "" {
			cur.Members = append(cur.Members, m)
		}
	}
	return out, rows.Err()
}
