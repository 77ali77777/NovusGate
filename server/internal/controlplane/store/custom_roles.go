package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

var (
	// ErrRoleNameTaken: another custom role has the name.
	ErrRoleNameTaken = errors.New("a role with this name exists")
	// ErrRoleInUse: users still have the role.
	ErrRoleInUse = errors.New("the role is given to users")
	// ErrRoleNotFound: no custom role has the id.
	ErrRoleNotFound = errors.New("role not found")
)

const roleColumns = `r.id, r.name, r.description, r.permissions, r.network_ids, r.scope_mode, r.max_networks, r.created_at, r.updated_at,
	(SELECT COUNT(*) FROM users u WHERE u.role_id = r.id)`

func scanRole(sc interface{ Scan(...any) error }) (*models.Role, error) {
	var r models.Role
	var perms []byte
	if err := sc.Scan(&r.ID, &r.Name, &r.Description, &perms, pq.Array(&r.NetworkIDs), &r.ScopeMode, &r.MaxNetworks, &r.CreatedAt, &r.UpdatedAt, &r.Users); err != nil {
		return nil, err
	}
	r.Permissions = map[string]string{}
	if err := json.Unmarshal(perms, &r.Permissions); err != nil {
		return nil, err
	}
	if r.NetworkIDs == nil {
		r.NetworkIDs = []string{}
	}
	return &r, nil
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

// ListRoles returns the custom roles by name, with how many users have each.
func (s *Store) ListRoles(ctx context.Context) ([]*models.Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+roleColumns+` FROM roles r ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRole returns a custom role, or nil.
func (s *Store) GetRole(ctx context.Context, id string) (*models.Role, error) {
	id, err := canonicalID(id)
	if err != nil {
		return nil, nil
	}
	r, err := scanRole(s.db.QueryRowContext(ctx, `SELECT `+roleColumns+` FROM roles r WHERE r.id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// CreateRole stores a new custom role (validated by the caller).
func (s *Store) CreateRole(ctx context.Context, r *models.Role) error {
	perms, err := json.Marshal(r.Permissions)
	if err != nil {
		return err
	}
	if r.NetworkIDs == nil {
		r.NetworkIDs = []string{}
	}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO roles (name, description, permissions, network_ids, scope_mode, max_networks) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`, r.Name, r.Description, perms, pq.Array(r.NetworkIDs), scopeOrAll(r.ScopeMode), r.MaxNetworks).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrRoleNameTaken
	}
	return err
}

// UpdateRole changes a custom role's name, description, permissions and
// networks; sql.ErrNoRows for an unknown role.
func (s *Store) UpdateRole(ctx context.Context, r *models.Role) error {
	id, err := canonicalID(r.ID)
	if err != nil {
		return err
	}
	perms, err := json.Marshal(r.Permissions)
	if err != nil {
		return err
	}
	if r.NetworkIDs == nil {
		r.NetworkIDs = []string{}
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE roles SET name = $2, description = $3, permissions = $4, network_ids = $5, scope_mode = $6, max_networks = $7, updated_at = NOW()
		WHERE id = $1`, id, r.Name, r.Description, perms, pq.Array(r.NetworkIDs), scopeOrAll(r.ScopeMode), r.MaxNetworks)
	if isUniqueViolation(err) {
		return ErrRoleNameTaken
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteRole deletes a custom role no user has; ErrRoleInUse otherwise.
func (s *Store) DeleteRole(ctx context.Context, id string) error {
	id, err := canonicalID(id)
	if err != nil {
		return err
	}
	var users int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role_id = $1`, id).Scan(&users); err != nil {
		return err
	}
	if users > 0 {
		return ErrRoleInUse
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23503" { // given to a user meanwhile
		return ErrRoleInUse
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetUserCustomRole gives a user a custom role; moving the last admin is
// ErrLastAdmin, an unknown user or role sql.ErrNoRows.
func (s *Store) SetUserCustomRole(ctx context.Context, userID, roleID string) error {
	userID, err := canonicalID(userID)
	if err != nil {
		return err
	}
	roleID, err = canonicalID(roleID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, err := otherAdmins(ctx, tx, userID)
	if err != nil {
		return err
	}
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = $1`, userID).Scan(&current); err != nil {
		return err
	}
	if current == "admin" && n == 0 {
		return ErrLastAdmin
	}
	// The role row is locked so it cannot be deleted before the user has it.
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE id = $1 FOR SHARE`, roleID).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = 'custom', role_id = $2 WHERE id = $1`, userID, roleID); err != nil {
		return err
	}
	return tx.Commit()
}
