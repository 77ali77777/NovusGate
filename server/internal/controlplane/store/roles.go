package store

import (
	"context"
	"database/sql"
	"errors"
)

// ErrLastAdmin: the change would leave the panel without an admin.
var ErrLastAdmin = errors.New("at least one admin must remain")

// ValidRole reports whether role is a panel role.
func ValidRole(role string) bool {
	return role == "admin" || role == "operator" || role == "viewer"
}

// otherAdmins locks the admin rows and counts the admins other than id, so
// two concurrent changes cannot both remove "the other" admin.
func otherAdmins(ctx context.Context, tx *sql.Tx, id string) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM users WHERE role = 'admin' FOR UPDATE`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return 0, err
		}
		if other != id {
			n++
		}
	}
	return n, rows.Err()
}

// SetUserRole changes a user's role; demoting the last admin is ErrLastAdmin.
func (s *Store) SetUserRole(ctx context.Context, id, role string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if role != "admin" {
		n, err := otherAdmins(ctx, tx, id)
		if err != nil {
			return err
		}
		var current string
		if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = $1`, id).Scan(&current); err != nil {
			return err // sql.ErrNoRows for an unknown user
		}
		if current == "admin" && n == 0 {
			return ErrLastAdmin
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE users SET role = $2 WHERE id = $1`, id, role)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// DeleteUserKeepingAdmin deletes a user unless it is the last admin.
func (s *Store) DeleteUserKeepingAdmin(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, err := otherAdmins(ctx, tx, id)
	if err != nil {
		return err
	}
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = $1`, id).Scan(&role); err != nil {
		return err
	}
	if role == "admin" && n == 0 {
		return ErrLastAdmin
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit()
}
