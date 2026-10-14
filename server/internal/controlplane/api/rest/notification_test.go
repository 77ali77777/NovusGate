package rest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/notify"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type recordingSender struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (r *recordingSender) Send(_ context.Context, token, chat, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.sent = append(r.sent, token+"|"+chat+"|"+text)
	return nil
}

func (r *recordingSender) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

func newNotifyServer(t *testing.T) (*Server, *recordingSender) {
	t.Helper()
	s, st, _ := newContractServer(t)
	if err := st.SaveNotificationSettings(context.Background(), models.NotificationSettings{
		NodeOffline: true, NodeExpired: true, Fail2BanBan: true, FirewallChange: true}, new(string)); err != nil {
		t.Fatal(err)
	}
	rs := &recordingSender{}
	s.SetNotifier(&notify.Notifier{Settings: st.NotificationSettings, Sender: rs, Now: time.Now, Repeat: time.Minute}, rs)
	return s, rs
}

const goodToken = "123456789:AAEexampleexampleexampleexample123"

func TestNotificationSettingsKeepTheTokenSecret(t *testing.T) {
	s, _ := newNotifyServer(t)

	put := callAs(t, s, "PUT", "/api/v1/notifications/settings",
		`{"enabled":true,"chat_id":"-1001234","bot_token":"`+goodToken+`","node_offline":true,"node_expired":false,"fail2ban_ban":true,"firewall_change":true}`, true)
	if put.Code != 200 || strings.Contains(put.Body.String(), goodToken) {
		t.Fatalf("put = %d %s", put.Code, put.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/notifications/settings", put)

	get := callAs(t, s, "GET", "/api/v1/notifications/settings", "", true)
	var got models.NotificationSettings
	json.Unmarshal(get.Body.Bytes(), &got)
	if get.Code != 200 || !got.Enabled || !got.TokenSet || got.ChatID != "-1001234" || got.NodeExpired ||
		strings.Contains(get.Body.String(), goodToken) {
		t.Fatalf("get = %d %s", get.Code, get.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/notifications/settings", get)

	// An empty token keeps the stored one.
	put = callAs(t, s, "PUT", "/api/v1/notifications/settings",
		`{"enabled":true,"chat_id":"@novus_alerts","bot_token":"","node_offline":true}`, true)
	_, token, _ := s.store.NotificationSettings(context.Background())
	if put.Code != 200 || token != goodToken {
		t.Fatalf("keep token: %d %s token kept=%v", put.Code, put.Body, token == goodToken)
	}

	if rec := callAs(t, s, "GET", "/api/v1/notifications/settings", "", false); rec.Code != 401 {
		t.Fatalf("unauthenticated = %d", rec.Code)
	}
}

func TestNotificationSettingsValidation(t *testing.T) {
	s, _ := newNotifyServer(t)
	for _, body := range []string{
		`{"enabled":true,"chat_id":"","bot_token":"` + goodToken + `"}`, // enabled without a chat
		`{"enabled":true,"chat_id":"42"}`,                               // enabled without any token
		`{"enabled":false,"chat_id":"not a chat","bot_token":""}`,       // bad chat ID
		`{"enabled":false,"chat_id":"42","bot_token":"nocolon"}`,        // bad token
		`{"enabled":false,"chat_id":"42","bot_token":"1:short"}`,        // bad token
	} {
		if rec := callAs(t, s, "PUT", "/api/v1/notifications/settings", body, true); rec.Code != 400 {
			t.Fatalf("%s = %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestNotificationTestMessage(t *testing.T) {
	s, rs := newNotifyServer(t)
	if rec := callAs(t, s, "POST", "/api/v1/notifications/test", "", true); rec.Code != 400 {
		t.Fatalf("unconfigured test = %d %s", rec.Code, rec.Body)
	}
	callAs(t, s, "PUT", "/api/v1/notifications/settings", `{"enabled":false,"chat_id":"42","bot_token":"`+goodToken+`"}`, true)
	rec := callAs(t, s, "POST", "/api/v1/notifications/test", "", true)
	if rec.Code != 200 || len(rs.messages()) != 1 || !strings.HasPrefix(rs.messages()[0], goodToken+"|42|") {
		t.Fatalf("test = %d %s sent %v", rec.Code, rec.Body, rs.messages())
	}
	assertMatchesSpec(t, s, "POST", "/api/v1/notifications/test", rec)

	rs.err = errors.New("telegram: Unauthorized")
	rec = callAs(t, s, "POST", "/api/v1/notifications/test", "", true)
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "Unauthorized") {
		t.Fatalf("failed test = %d %s", rec.Code, rec.Body)
	}
}

// A successful firewall change notifies; reads and failed changes do not.
func TestFirewallChangeNotifies(t *testing.T) {
	s, rs := newNotifyServer(t)
	callAs(t, s, "PUT", "/api/v1/notifications/settings",
		`{"enabled":true,"chat_id":"42","bot_token":"`+goodToken+`","firewall_change":true}`, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.notifier.Run(ctx)

	callAs(t, s, "GET", "/api/v1/firewall/vpn/rules", "", true)
	callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":""}`, true) // 400
	// A disabled rule is stored without touching the host.
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules",
		`{"name":"notify-test","source_type":"any","dest_type":"any","protocol":"all","action":"accept","enabled":false}`, true)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(rs.messages()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := rs.messages()
	if len(got) != 1 || !strings.Contains(got[0], "POST /api/v1/firewall/vpn/rules") {
		t.Fatalf("sent = %v", got)
	}
}
