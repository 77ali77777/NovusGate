package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// Own networks (2026-10-20): a role may let each user create networks of
// their own, up to a limit; the user sees only those.
func TestOwnedNetworkLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u := &models.User{Username: "owner-1", PasswordHash: "x", Role: "viewer"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM users WHERE id = $1", u.ID) })
	mk := func(name string, port int) *models.Network {
		return &models.Network{Name: name, CIDR: "10.20" + string(rune('0'+port%10)) + ".0.0/24", ListenPort: 52000 + port, InterfaceName: "wgo" + string(rune('0'+port))}
	}
	a := mk("own-a", 1)
	if err := s.CreateOwnedNetwork(ctx, a, u.ID, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.db.ExecContext(context.Background(), "DELETE FROM networks WHERE owner_user_id IS NOT NULL OR name LIKE 'own-%'")
	})
	if a.OwnerUserID == nil || *a.OwnerUserID != u.ID {
		t.Fatalf("owner = %v", a.OwnerUserID)
	}
	if err := s.CreateOwnedNetwork(ctx, mk("own-b", 2), u.ID, 1); !errors.Is(err, ErrNetworkLimit) {
		t.Fatalf("over the limit = %v", err)
	}
	ids, err := s.NetworksOwnedBy(ctx, u.ID)
	if err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("owned = %v %v", ids, err)
	}
	got, _ := s.GetNetwork(ctx, a.ID)
	if got.OwnerUserID == nil || *got.OwnerUserID != u.ID {
		t.Fatalf("stored owner = %v", got.OwnerUserID)
	}
	if err := s.SetNetworkOwner(ctx, a.ID, nil); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.NetworksOwnedBy(ctx, u.ID); len(ids) != 0 {
		t.Fatalf("handed over: %v", ids)
	}
	// Deleting the user keeps the network, without an owner.
	if err := s.SetNetworkOwner(ctx, a.ID, &u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetNetwork(ctx, a.ID); got == nil || got.OwnerUserID != nil {
		t.Fatalf("after the user is gone: %+v", got)
	}
}

func TestRoleScopeModeStored(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	r := &models.Role{Name: "own-scope", Permissions: map[string]string{"networks": "edit"}, ScopeMode: "own", MaxNetworks: 3}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM roles WHERE id = $1", r.ID) })
	got, err := s.GetRole(ctx, r.ID)
	if err != nil || got.ScopeMode != "own" || got.MaxNetworks != 3 {
		t.Fatalf("got = %+v %v", got, err)
	}
}

// The 026 rollback runs with an own-scope role, and
// the role loses its permissions (without scope_mode it would see every
// network).
func TestNetworkOwnerRollback(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	r := &models.Role{Name: "own-down", Permissions: map[string]string{"networks": "edit"}, ScopeMode: "own", MaxNetworks: 1}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.ExecContext(context.Background(), "DELETE FROM roles WHERE id = $1", r.ID) })
	down, err := os.ReadFile("migrations_rollback/026_network_owner.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("migrations_sql/026_network_owner.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var perms string
	s.db.QueryRowContext(ctx, `SELECT permissions::text FROM roles WHERE id = $1`, r.ID).Scan(&perms)
	// Up again (restores the schema the other tests use).
	if _, err := s.db.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("up: %v", err)
	}
	if perms != "{}" {
		t.Fatalf("own role keeps permissions after the rollback: %s", perms)
	}
}
