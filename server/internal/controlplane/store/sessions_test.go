package store

import (
	"context"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestSessionsLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM users WHERE username LIKE 'sess-%'")
	u := &models.User{Username: "sess-a", PasswordHash: "x"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteUser(context.Background(), u.ID) })
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, h := range []string{"h1", "h2"} {
		if err := s.CreateSession(ctx, u.ID, h, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.SessionUser(ctx, "h1", now.Add(59*time.Minute)); err != nil || got == nil || got.Username != "sess-a" {
		t.Fatalf("valid session = %v, %v", got, err)
	}
	if got, _ := s.SessionUser(ctx, "h1", now.Add(61*time.Minute)); got != nil {
		t.Fatal("an expired session must not resolve")
	}
	if got, _ := s.SessionUser(ctx, "nope", now); got != nil {
		t.Fatal("an unknown hash must not resolve")
	}
	if err := s.TouchSession(ctx, "h1", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserSessions(ctx, u.ID, "h2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SessionUser(ctx, "h1", now); got != nil {
		t.Fatal("h1 must be revoked")
	}
	if got, _ := s.SessionUser(ctx, "h2", now); got == nil {
		t.Fatal("the excepted session must survive")
	}
	if err := s.DeleteExpiredSessions(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SessionUser(ctx, "h2", now); got != nil {
		t.Fatal("expired sessions must be deleted")
	}
	// Deleting the user cascades to its sessions.
	if err := s.CreateSession(ctx, u.ID, "h3", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "h3"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SessionUser(ctx, "h3", now); got != nil {
		t.Fatal("h3 must be deleted")
	}
	s.CreateSession(ctx, u.ID, "h4", now, time.Hour)
	s.DeleteUser(ctx, u.ID)
	var n int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM sessions WHERE token_hash = 'h4'").Scan(&n)
	if n != 0 {
		t.Fatal("user deletion must remove its sessions")
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM users WHERE username = 'sess-pw'")
	u := &models.User{Username: "sess-pw", PasswordHash: "old"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteUser(context.Background(), u.ID) })
	now := time.Now()
	s.CreateSession(ctx, u.ID, "keep", now, time.Hour)
	s.CreateSession(ctx, u.ID, "drop", now, time.Hour)
	if err := s.ChangePassword(ctx, u.ID, "new-hash", "keep"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUserByUsername(ctx, "sess-pw")
	if got.PasswordHash != "new-hash" {
		t.Fatalf("hash = %q", got.PasswordHash)
	}
	if u, _ := s.SessionUser(ctx, "drop", now); u != nil {
		t.Fatal("other sessions must be revoked")
	}
	if u, _ := s.SessionUser(ctx, "keep", now); u == nil {
		t.Fatal("the current session must stay")
	}
}

// /health only needs interface names, not whole network rows (keys).
func TestListInterfaceNames(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM networks WHERE name = 'iface-net'")
	nw := &models.Network{Name: "iface-net", CIDR: "10.74.0.0/24", ListenPort: 51874, InterfaceName: "wg74"}
	if err := s.CreateNetwork(ctx, nw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), nw.ID) })
	names, err := s.ListInterfaceNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range names {
		if n == "" {
			t.Fatal("empty interface names must not be listed")
		}
		found = found || n == "wg74"
	}
	if !found {
		t.Fatalf("names = %v, want wg74 among them", names)
	}
}
