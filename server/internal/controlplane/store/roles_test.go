package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// The last admin stays an admin however its UUID is spelled: Postgres
// accepts upper case and braces, so the guard must not compare strings.
func TestLastAdminGuardIgnoresIDSpelling(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM users"); err != nil {
		t.Fatal(err)
	}
	u := &models.User{Username: "only-admin", PasswordHash: "x", Role: "admin"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM users WHERE id = $1", u.ID) })

	for _, id := range []string{strings.ToUpper(u.ID), "{" + u.ID + "}"} {
		if err := s.SetUserRole(ctx, id, "viewer"); !errors.Is(err, ErrLastAdmin) {
			t.Errorf("SetUserRole(%s) = %v, want ErrLastAdmin", id, err)
		}
		if err := s.DeleteUserKeepingAdmin(ctx, id); !errors.Is(err, ErrLastAdmin) {
			t.Errorf("DeleteUserKeepingAdmin(%s) = %v, want ErrLastAdmin", id, err)
		}
	}
	// An id that is not a UUID is an unknown user, not a database error.
	if err := s.SetUserRole(ctx, "not-a-uuid", "viewer"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("SetUserRole(bad id) = %v, want sql.ErrNoRows", err)
	}
	if err := s.DeleteUserKeepingAdmin(ctx, "not-a-uuid"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("DeleteUserKeepingAdmin(bad id) = %v, want sql.ErrNoRows", err)
	}
	var role string
	s.db.QueryRowContext(ctx, "SELECT role FROM users WHERE id = $1", u.ID).Scan(&role)
	if role != "admin" {
		t.Fatalf("role = %q, the last admin was demoted", role)
	}
}
