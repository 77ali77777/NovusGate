package store

import (
	"context"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestNotificationSettingsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM notification_settings"); err != nil {
		t.Fatal(err)
	}

	// No row yet: disabled, every event switched on, no token.
	got, token, err := s.NotificationSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.TokenSet || token != "" || !got.NodeOffline || !got.FirewallChange {
		t.Fatalf("defaults = %+v token %q", got, token)
	}

	tok := "123456:SECRET-TOKEN"
	in := models.NotificationSettings{Enabled: true, ChatID: "-100200", NodeOffline: true, Fail2BanBan: true}
	if err := s.SaveNotificationSettings(ctx, in, &tok); err != nil {
		t.Fatal(err)
	}
	got, token, err = s.NotificationSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.ChatID != "-100200" || !got.TokenSet || token != tok || got.NodeExpired || !got.Fail2BanBan {
		t.Fatalf("saved = %+v token %q", got, token)
	}

	// The token is stored sealed (with a box) or prefixed, never as given.
	var stored string
	if err := s.db.QueryRowContext(ctx, "SELECT bot_token_enc FROM notification_settings").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == tok || !strings.Contains(stored, ":") {
		t.Fatalf("stored token = %q", stored)
	}

	// nil keeps the token; other fields change.
	in.ChatID = "777"
	if err := s.SaveNotificationSettings(ctx, in, nil); err != nil {
		t.Fatal(err)
	}
	got, token, _ = s.NotificationSettings(ctx)
	if got.ChatID != "777" || token != tok {
		t.Fatalf("after keep = %+v token %q", got, token)
	}
}
