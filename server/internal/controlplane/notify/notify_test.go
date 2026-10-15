package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

func TestTelegramSendsMessage(t *testing.T) {
	var got struct {
		path string
		body map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		json.NewDecoder(r.Body).Decode(&got.body)
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	tg := &Telegram{BaseURL: srv.URL, Client: srv.Client()}
	if err := tg.Send(context.Background(), "123:ABC", "-100", "hello"); err != nil {
		t.Fatal(err)
	}
	if got.path != "/bot123:ABC/sendMessage" || got.body["chat_id"] != "-100" || got.body["text"] != "hello" {
		t.Fatalf("request = %+v", got)
	}
}

// Telegram's description is passed on (wrong chat, revoked token), but the
// token, which is part of the URL, never appears in the error.
func TestTelegramErrorKeepsTokenOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"ok":false,"description":"Bad Request: chat not found"}`)
	}))
	defer srv.Close()
	tg := &Telegram{BaseURL: srv.URL, Client: srv.Client()}
	err := tg.Send(context.Background(), "123:SECRET", "-1", "x")
	if err == nil || !strings.Contains(err.Error(), "chat not found") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
	down := &Telegram{BaseURL: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}}
	if err := down.Send(context.Background(), "123:SECRET", "-1", "x"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("network error = %v", err)
	}
}

type fakeSender struct {
	mu   sync.Mutex
	sent []string
}

func (f *fakeSender) Send(_ context.Context, token, chat, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, token+"|"+chat+"|"+text)
	return nil
}

func (f *fakeSender) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func newNotifier(settings models.NotificationSettings) (*Notifier, *fakeSender, *time.Time) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	fs := &fakeSender{}
	n := &Notifier{
		Settings: func(context.Context) (models.NotificationSettings, string, error) { return settings, "TOKEN", nil },
		Sender:   fs,
		Now:      func() time.Time { return now },
		Repeat:   10 * time.Minute,
	}
	return n, fs, &now
}

func TestNotifierFiltersByEventAndDeduplicates(t *testing.T) {
	n, fs, now := newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", NodeOffline: true})
	ctx := context.Background()
	n.Deliver(ctx, Event{Kind: NodeOffline, Key: "a", Text: "node a is offline"})
	n.Deliver(ctx, Event{Kind: NodeOffline, Key: "a", Text: "node a is offline"}) // within Repeat
	n.Deliver(ctx, Event{Kind: Fail2BanBan, Key: "1.2.3.4", Text: "banned"})      // event off
	*now = now.Add(11 * time.Minute)
	n.Deliver(ctx, Event{Kind: NodeOffline, Key: "a", Text: "node a is offline"})
	got := fs.messages()
	if len(got) != 2 || got[0] != "TOKEN|42|node a is offline" {
		t.Fatalf("sent = %v", got)
	}
}

func TestNotifierDisabledOrIncompleteSendsNothing(t *testing.T) {
	for _, s := range []models.NotificationSettings{
		{Enabled: false, ChatID: "42", NodeOffline: true},
		{Enabled: true, ChatID: "", NodeOffline: true},
	} {
		n, fs, _ := newNotifier(s)
		n.Deliver(context.Background(), Event{Kind: NodeOffline, Key: "a", Text: "x"})
		if len(fs.messages()) != 0 {
			t.Fatalf("%+v sent %v", s, fs.messages())
		}
	}
	n, fs, _ := newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", NodeOffline: true})
	n.Settings = func(context.Context) (models.NotificationSettings, string, error) {
		return models.NotificationSettings{Enabled: true, ChatID: "42", NodeOffline: true}, "", nil // no token
	}
	n.Deliver(context.Background(), Event{Kind: NodeOffline, Key: "a", Text: "x"})
	if len(fs.messages()) != 0 {
		t.Fatal("no token, no message")
	}
}

// Notify never blocks the caller: events go through a queue.
func TestNotifyIsAsynchronous(t *testing.T) {
	n, fs, _ := newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", FirewallChange: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Notify(Event{Kind: FirewallChange, Key: "k", Text: "changed"})
	deadline := time.Now().Add(2 * time.Second)
	for len(fs.messages()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(fs.messages()) != 1 {
		t.Fatal("queued event not delivered")
	}
}

func TestPeerWatcherReportsTransitions(t *testing.T) {
	n, fs, _ := newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", NodeOffline: true})
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	hs := now.Add(-30 * time.Second).Unix()
	w := &PeerWatcher{
		Notifier: n,
		Now:      func() time.Time { return now },
		Nodes: func(context.Context) ([]WatchedNode, error) {
			return []WatchedNode{{ID: "a", Name: "laptop-01", Network: "branch", Interface: "wg1", PublicKey: "KA"}}, nil
		},
		Peers: func(string) (map[string]wireguard.PeerStatus, error) {
			return map[string]wireguard.PeerStatus{"KA": {PublicKey: "KA", LatestHandshakeTime: hs}}, nil
		},
	}
	ctx := context.Background()
	w.RunOnce(ctx) // first sight: online, no message
	hs = now.Add(-4 * time.Minute).Unix()
	w.RunOnce(ctx) // between the thresholds: still online
	hs = now.Add(-6 * time.Minute).Unix()
	w.RunOnce(ctx) // offline
	hs = now.Add(-10 * time.Second).Unix()
	w.RunOnce(ctx) // back online
	got := fs.messages()
	if len(got) != 2 || !strings.Contains(got[0], "laptop-01") || !strings.Contains(got[0], "offline") || !strings.Contains(got[1], "back online") {
		t.Fatalf("sent = %v", got)
	}
}

func TestFail2BanWatcherReportsNewBansOnly(t *testing.T) {
	n, fs, _ := newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", Fail2BanBan: true})
	log := filepath.Join(t.TempDir(), "fail2ban.log")
	os.WriteFile(log, []byte("2026-10-15 11:00:00,000 fail2ban.actions [1]: NOTICE [sshd] Ban 198.51.100.9\n"), 0o600)
	w := &Fail2BanWatcher{Notifier: n, Path: log}
	ctx := context.Background()
	w.RunOnce(ctx) // existing lines are history, not news
	f, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("2026-10-15 12:00:01,000 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.7\n")
	f.WriteString("2026-10-15 12:00:02,000 fail2ban.actions [1]: NOTICE [sshd] Unban 192.0.2.1\n")
	f.Close()
	w.RunOnce(ctx)
	got := fs.messages()
	if len(got) != 1 || !strings.Contains(got[0], "203.0.113.7") || !strings.Contains(got[0], "sshd") {
		t.Fatalf("sent = %v", got)
	}
	// log rotation: a shorter file starts over
	os.WriteFile(log, []byte("2026-10-15 12:05:00,000 fail2ban.actions [1]: NOTICE [recidive] Ban 192.0.2.50\n"), 0o600)
	w.RunOnce(ctx)
	if got := fs.messages(); len(got) != 2 || !strings.Contains(got[1], "192.0.2.50") {
		t.Fatalf("after rotation = %v", got)
	}
}

func TestSettingsErrorIsNotFatal(t *testing.T) {
	n, fs, _ := newNotifier(models.NotificationSettings{})
	n.Settings = func(context.Context) (models.NotificationSettings, string, error) {
		return models.NotificationSettings{}, "", errors.New("db down")
	}
	n.Deliver(context.Background(), Event{Kind: NodeOffline, Key: "a", Text: "x"})
	if len(fs.messages()) != 0 {
		t.Fatal("no settings, no message")
	}
}

// Quota events (P9c) follow their own switch.
func TestQuotaEventsFollowTheirSwitch(t *testing.T) {
	ctx := context.Background()
	n, fs, _ := newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", QuotaExceeded: true})
	n.Deliver(ctx, Event{Kind: QuotaExceeded, Key: "n1:p:100", Text: "over quota"})
	if len(fs.messages()) != 1 {
		t.Fatal("quota event not sent")
	}
	n, fs, _ = newNotifier(models.NotificationSettings{Enabled: true, ChatID: "42", FirewallChange: true})
	n.Deliver(ctx, Event{Kind: QuotaExceeded, Key: "n1:p:100", Text: "over quota"})
	if len(fs.messages()) != 0 {
		t.Fatal("quota switch off: nothing must be sent")
	}
}
