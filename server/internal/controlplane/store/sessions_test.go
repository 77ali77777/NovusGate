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
