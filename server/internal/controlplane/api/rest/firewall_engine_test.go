package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// recRunner is a fake host: it records nft scripts instead of loading them.
type recRunner struct {
	mu      sync.Mutex
	applied []string
}

func (r *recRunner) Run(stdin, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := strings.Join(append([]string{name}, args...), " ")
	switch cmd {
	case "nft -f -":
		r.applied = append(r.applied, stdin)
	case "nft list table inet novusgate":
		return "table inet novusgate {\n}\n", nil
	}
	return "", nil
}

func (r *recRunner) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return ""
	}
	return r.applied[len(r.applied)-1]
}

type recTimer struct{ active bool }

func (t *recTimer) Arm(string, time.Duration) error { t.active = true; return nil }
func (t *recTimer) Disarm() error                   { t.active = false; return nil }
func (t *recTimer) Active() (bool, error)           { return t.active, nil }

// newEngineServer builds a Server on TEST_DATABASE_URL with an engine whose
// host is faked. The firewall tables are emptied first.
func newEngineServer(t *testing.T, mode firewall.Mode) (*Server, *recRunner) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run database tests (scripts/test-with-postgres.sh)")
	}
	st, err := store.New(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetFirewallHostRules(ctx); err != nil {
		t.Fatal(err)
	}
	forwards, _ := st.ListFirewallForwards(ctx)
	for _, f := range forwards {
		st.DeleteFirewallForward(ctx, f.ID)
	}

	// Never touch the machine running the tests.
	origClear, origPeers := clearLegacyVPNRules, adminPeers
	clearLegacyVPNRules = func(*Server) error { return nil }
	adminPeers = func() (map[string]wireguard.PeerStatus, error) { return nil, nil }
	t.Cleanup(func() { clearLegacyVPNRules, adminPeers = origClear, origPeers })

	r := &recRunner{}
	applier := &nft.SafeApplier{
		Exec: nft.Executor{Runner: r}, Timer: &recTimer{}, Timeout: time.Minute, Grace: 15 * time.Second,
		Now:       time.Now,
		AfterFunc: func(time.Duration, func()) func() bool { return func() bool { return true } },
	}
	s := &Server{store: st, router: mux.NewRouter(), managers: map[string]*wireguard.Manager{},
		peerActivity: map[string]*PeerActivity{}}
	s.setupRoutes()
	s.SetFirewall(&firewall.Engine{
		Mode: mode, Store: st, Applier: applier, Now: time.Now,
		Detect: func() (firewall.HostInfo, error) {
			return firewall.HostInfo{SSHPorts: []uint16{22}, Egress: "eth0"}, nil
		},
		Persist: func(string) error { return nil },
	})
	return s, r
}

func call(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.200:5555" // the operator
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func inputRules(t *testing.T, s *Server) FirewallStatus {
	t.Helper()
	rec := call(t, s, "GET", "/api/v1/firewall/host/rules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET rules = %d %s", rec.Code, rec.Body)
	}
	var st FirewallStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func findRule(st FirewallStatus, proto, port string) (FirewallRule, bool) {
	for _, c := range st.Chains {
		for _, r := range c.Rules {
			if r.Protocol == proto && r.Port == port {
				return r, true
			}
		}
	}
	return FirewallRule{}, false
}

func TestLegacyPortEndpointsInNftMode(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)

	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/open", `{"port":443,"protocol":"both"}`); rec.Code != 200 {
		t.Fatalf("open = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(r.last(), "tcp dport 443 accept") || !strings.Contains(r.last(), "udp dport 443 accept") {
		t.Fatalf("both protocols must be applied:\n%s", r.last())
	}
	st := inputRules(t, s)
	if _, ok := findRule(st, "tcp", "443"); !ok {
		t.Fatal("the legacy view must list the opened port")
	}
	if ssh, ok := findRule(st, "tcp", "22"); !ok || !ssh.Protected || ssh.Number != 1 {
		t.Fatalf("SSH must be listed first and protected: %+v", ssh)
	}

	rec := call(t, s, "POST", "/api/v1/firewall/host/port/close", `{"port":443,"protocol":"tcp"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rules_deleted":1`) {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
	udp, _ := findRule(inputRules(t, s), "udp", "443")
	body := `{"chain":"INPUT","line_number":` + itoa(udp.Number) + `}`
	if rec := call(t, s, "POST", "/api/v1/firewall/host/rules/delete", body); rec.Code != 200 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, ok := findRule(inputRules(t, s), "udp", "443"); ok {
		t.Fatal("the deleted rule must be gone")
	}

	if rec := call(t, s, "POST", "/api/v1/firewall/host/rules/delete", `{"chain":"INPUT","line_number":1,"force":true}`); rec.Code != http.StatusForbidden {
		t.Fatalf("deleting the SSH rule must be forbidden even with force, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/close", `{"port":22,"protocol":"tcp"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("closing SSH without force must be forbidden, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/import", `{"rules":"*filter\nCOMMIT\n"}`); rec.Code != http.StatusConflict {
		t.Fatalf("iptables import must be refused in nft mode, got %d", rec.Code)
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/host/export", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "table inet novusgate") {
		t.Fatalf("export = %d %s", rec.Code, rec.Body)
	}
}

func TestLegacyIPEndpointsAndPermanentBansInNftMode(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)

	for _, body := range []string{`{"ip":"203.0.113.7","ports":"80,443"}`, `{"ip":"198.51.100.9"}`} {
		if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", body); rec.Code != 200 {
			t.Fatalf("block %s = %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/allow", `{"ip":"192.0.2.0/24"}`); rec.Code != 200 {
		t.Fatalf("allow = %d %s", rec.Code, rec.Body)
	}
	script := r.last()
	for _, want := range []string{"ip saddr 203.0.113.7 tcp dport { 80, 443 } counter drop", "elements = { 198.51.100.9 }", "ip saddr 192.0.2.0/24 accept"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in\n%s", want, script)
		}
	}
	if st := inputRules(t, s); st.BlockedIPs != 2 {
		t.Fatalf("blocked_ips = %d, want 2", st.BlockedIPs)
	}

	// Blocking the network the operator comes from must be refused.
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", `{"ip":"198.51.100.0/24"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-block = %d %s", rec.Code, rec.Body)
	}

	if rec := call(t, s, "POST", "/api/v1/system/fail2ban/ban", `{"jail":"sshd","ip":"203.0.113.99","permanent":true}`); rec.Code != 200 {
		t.Fatalf("permanent ban = %d %s", rec.Code, rec.Body)
	}
	rec := call(t, s, "GET", "/api/v1/system/fail2ban/permanent-bans", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"count":2`) || !strings.Contains(rec.Body.String(), `"ip":"203.0.113.99"`) {
		t.Fatalf("permanent bans = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "DELETE", "/api/v1/system/fail2ban/permanent-bans", `{"ip":"203.0.113.99"}`); rec.Code != 200 {
		t.Fatalf("unban = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "GET", "/api/v1/system/fail2ban/permanent-bans", ""); !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Fatalf("after unban: %s", rec.Body)
	}

	if rec := call(t, s, "POST", "/api/v1/firewall/host/reset", ""); rec.Code != 200 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if st := inputRules(t, s); st.BlockedIPs != 0 {
		t.Fatal("reset must remove panel blocks")
	}
}

func TestV2ChangesWaitForConfirmation(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	ctx := context.Background()
	net := &models.Network{Name: "fw-rest-test", CIDR: "10.20.0.0/24", InterfaceName: "wg91", ListenPort: 51991}
	if err := s.store.CreateNetwork(ctx, net); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), net.ID) })

	rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`)
	var resp struct {
		Pending *struct{ ID string } `json:"pending"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Pending == nil {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(r.last(), "tcp dport 9443 accept") {
		t.Fatal("the change must be live while it waits for confirmation")
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/v2/state", ""); !strings.Contains(rec.Body.String(), `"services":[]`) {
		t.Fatalf("nothing may be stored before confirmation: %s", rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/open", `{"port":80,"protocol":"tcp"}`); rec.Code != http.StatusConflict {
		t.Fatalf("other changes must wait while one is pending, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/confirm/"+resp.Pending.ID, ""); rec.Code != 200 {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/v2/state", ""); !strings.Contains(rec.Body.String(), `"port_from":9443`) {
		t.Fatalf("confirmed change must be stored: %s", rec.Body)
	}

	rec = call(t, s, "POST", "/api/v1/firewall/v2/forwards?confirm=false",
		`{"protocol":"tcp","public_port":8081,"target_ip":"10.20.0.5","target_port":80}`)
	if rec.Code != 200 || !strings.Contains(r.last(), "dnat ip to 10.20.0.5:80") {
		t.Fatalf("forward = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/forwards?confirm=false",
		`{"protocol":"tcp","public_port":22,"target_ip":"10.20.0.5","target_port":22}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a forward on the SSH port must be rejected, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"sctp","port_from":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid input must be 400, got %d", rec.Code)
	}
}

func TestV2DisabledOutsideNftMode(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeShadow)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`); rec.Code != http.StatusConflict {
		t.Fatalf("v2 changes in shadow mode = %d, want 409", rec.Code)
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/v2/preview", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "table inet novusgate") {
		t.Fatalf("preview works in every mode: %d %s", rec.Code, rec.Body)
	}
	if len(r.applied) != 0 {
		t.Fatal("nothing may be applied outside nft mode")
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// The legacy iptables VPN rules may only be removed once nftables enforces
// the VPN policy; otherwise a failed startup apply would leave the FORWARD
// chain without isolation.
func TestLegacyVPNRulesStayUntilTheEngineApplies(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	ctx := context.Background()
	if err := s.store.SetFirewallMeta(ctx, firewall.ImportedKey, "test"); err != nil {
		t.Fatal(err)
	}
	cleared := 0
	orig := clearLegacyVPNRules
	clearLegacyVPNRules = func(*Server) error { cleared++; return nil }
	t.Cleanup(func() { clearLegacyVPNRules = orig })

	timer := s.firewall.Applier.Timer.(*recTimer)
	timer.active = true // a rollback armed before the restart
	if err := s.StartFirewall(ctx); err == nil {
		t.Fatal("startup apply must fail while a rollback timer is armed")
	}
	if cleared != 0 || r.last() != "" {
		t.Fatalf("nothing may change while the engine could not apply (cleared=%d)", cleared)
	}

	timer.active = false
	s.reconcileFirewall(ctx)
	s.reconcileFirewall(ctx)
	if cleared != 1 || r.last() == "" {
		t.Fatalf("the legacy rules must be removed once, after the first apply (cleared=%d)", cleared)
	}
}
