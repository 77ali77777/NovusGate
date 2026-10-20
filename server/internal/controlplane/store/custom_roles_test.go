package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// Custom roles (2026-10-20): an admin defines which sections a role sees
// or changes, and optionally the networks it is limited to; users get one.
func TestCustomRoles(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	r := &models.Role{Name: "office manager", Description: "devices of the office",
		Permissions: map[string]string{"devices": "edit", "networks": "view"}, NetworkIDs: []string{}}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM roles WHERE id = $1", r.ID) })
	if r.ID == "" {
		t.Fatal("no id")
	}
	if err := s.CreateRole(ctx, &models.Role{Name: "office manager"}); !errors.Is(err, ErrRoleNameTaken) {
		t.Fatalf("same name = %v", err)
	}

	u := &models.User{Username: "maria-custom", PasswordHash: "x", Role: "viewer"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM users WHERE id = $1", u.ID) })
	if err := s.SetUserCustomRole(ctx, u.ID, r.ID); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRole(ctx, r.ID)
	if err != nil || got == nil || got.Permissions["devices"] != "edit" || got.Users != 1 {
		t.Fatalf("get = %+v %v", got, err)
	}
	got.Permissions["devices"] = "view"
	got.NetworkIDs = []string{"00000000-0000-0000-0000-000000000001"}
	if err := s.UpdateRole(ctx, got); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListRoles(ctx)
	if err != nil || len(list) == 0 {
		t.Fatalf("list = %v %v", list, err)
	}
	for _, x := range list {
		if x.ID == r.ID && (x.Permissions["devices"] != "view" || len(x.NetworkIDs) != 1) {
			t.Fatalf("updated: %+v", x)
		}
	}

	// The session carries the custom role.
	if err := s.CreateSession(ctx, u.ID, "custom-role-hash", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	su, err := s.SessionUser(ctx, "custom-role-hash", time.Now())
	if err != nil || su == nil || su.Role != "custom" || su.RoleID == nil || *su.RoleID != r.ID {
		t.Fatalf("session user = %+v %v", su, err)
	}

	if err := s.DeleteRole(ctx, r.ID); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("delete in use = %v", err)
	}
	if err := s.SetUserRole(ctx, u.ID, "viewer"); err != nil {
		t.Fatal(err)
	}
	if su, _ := s.SessionUser(ctx, "custom-role-hash", time.Now()); su.Role != "viewer" || su.RoleID != nil {
		t.Fatalf("back to a built-in role: %+v", su)
	}
	if err := s.DeleteRole(ctx, r.ID); err != nil {
		t.Fatalf("delete unused = %v", err)
	}
}

// Moving the last admin to a custom role leaves no admin: refused.
func TestCustomRoleKeepsAnAdmin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM users"); err != nil {
		t.Fatal(err)
	}
	u := &models.User{Username: "only-admin-2", PasswordHash: "x", Role: "admin"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM users WHERE id = $1", u.ID) })
	r := &models.Role{Name: "lone", Permissions: map[string]string{}}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM roles WHERE id = $1", r.ID) })
	if err := s.SetUserCustomRole(ctx, u.ID, r.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin to custom = %v", err)
	}
}
