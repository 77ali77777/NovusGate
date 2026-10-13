package firewall

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type memStore struct {
	networks []*models.Network
	services []*models.FirewallService
	ipRules  []*models.FirewallIPRule
	forwards []*models.FirewallForward
	egress   []string
	nodes    map[string]*models.Node
	meta     map[string]string
	imports  int
}

func (m *memStore) ListNetworks(context.Context) ([]*models.Network, error) { return m.networks, nil }
func (m *memStore) ListVPNFirewallRules(context.Context) ([]*models.VPNFirewallRule, error) {
	return nil, nil
}
func (m *memStore) GetNode(_ context.Context, id string) (*models.Node, error) {
	return m.nodes[id], nil
}
func (m *memStore) ListFirewallServices(context.Context) ([]*models.FirewallService, error) {
	return append([]*models.FirewallService(nil), m.services...), nil
}
func (m *memStore) ListFirewallIPRules(context.Context) ([]*models.FirewallIPRule, error) {
	return append([]*models.FirewallIPRule(nil), m.ipRules...), nil
}
func (m *memStore) ListFirewallForwards(context.Context) ([]*models.FirewallForward, error) {
	return m.forwards, nil
}
func (m *memStore) ListEgressNodeIDs(context.Context) ([]string, error) { return m.egress, nil }
func (m *memStore) GetFirewallMeta(_ context.Context, k string) (string, bool, error) {
	v, ok := m.meta[k]
	return v, ok, nil
}
func (m *memStore) ImportFirewallRules(_ context.Context, s []*models.FirewallService, r []*models.FirewallIPRule, k, v string) error {
	m.imports++
	m.services = append(m.services, s...)
	m.ipRules = append(m.ipRules, r...)
	if m.meta == nil {
		m.meta = map[string]string{}
	}
	m.meta[k] = v
	return nil
}

// nftRunner records nft invocations against a fake host.
type nftRunner struct {
	applied []string
	checked int
	iptS    string
}

func (r *nftRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	switch cmd {
	case "nft -f -":
		r.applied = append(r.applied, stdin)
	case "nft -c -f -":
		r.checked++
	case "nft list table inet novusgate":
		return "", errors.New("nft: Error: No such file or directory")
	case "iptables -S INPUT":
		return r.iptS, nil
	}
	return "", nil
}

type hostTimer struct{ active bool }

func (t *hostTimer) Arm(string, time.Duration) error { t.active = true; return nil }
func (t *hostTimer) Disarm() error                   { t.active = false; return nil }
func (t *hostTimer) Active() (bool, error)           { return t.active, nil }

var engineNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type harness struct {
	e         *Engine
	st        *memStore
	r         *nftRunner
	persisted []string
	rollback  func()
	expiryIn  time.Duration
}

func newHarness(mode Mode) *harness {
	h := &harness{
		st: &memStore{
			networks: []*models.Network{{ID: "n1", Name: "Office", CIDR: "10.20.0.0/24", InterfaceName: "wg1", ListenPort: 51821}},
			nodes:    map[string]*models.Node{"node-7": {ID: "node-7", VirtualIP: net.ParseIP("10.20.0.7")}},
		},
		r: &nftRunner{},
	}
	applier := &nft.SafeApplier{
		Exec: nft.Executor{Runner: h.r}, Timer: &hostTimer{}, Timeout: time.Minute,
		Now: func() time.Time { return engineNow },
		AfterFunc: func(_ time.Duration, f func()) func() bool {
			h.rollback = f
			return func() bool { h.rollback = nil; return true }
		},
	}
	h.e = &Engine{
		Mode: mode, Store: h.st, Applier: applier, Now: func() time.Time { return engineNow },
		Detect:  func() (HostInfo, error) { return HostInfo{SSHPorts: []uint16{22}, Egress: "eth0"}, nil },
		Persist: func(s string) error { h.persisted = append(h.persisted, s); return nil },
		AfterFunc: func(d time.Duration, f func()) func() bool {
			h.expiryIn = d
			return func() bool { return true }
		},
	}
	return h
}

func openPort(h *harness, port int, commits *int) Change {
	svc := &models.FirewallService{ID: "11111111-1111-1111-1111-111111111111", Protocol: "tcp", PortFrom: port, PortTo: port, Sources: []string{}}
	return Change{
		Mutate: func(st *State) error { st.Services = append(st.Services, svc); return nil },
		Commit: func(context.Context) error { *commits++; h.st.services = append(h.st.services, svc); return nil },
	}
}

func TestEngineDisabledOutsideNftMode(t *testing.T) {
	for _, mode := range []Mode{ModeIptables, ModeShadow} {
		h := newHarness(mode)
		commits := 0
		if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); !errors.Is(err, ErrEngineDisabled) {
			t.Fatalf("%s: got %v, want ErrEngineDisabled", mode, err)
		}
		if len(h.r.applied) != 0 || commits != 0 {
			t.Fatalf("%s: nothing may be applied or stored", mode)
		}
	}
}

func TestProposeImmediateAppliesStoresAndPersists(t *testing.T) {
	h := newHarness(ModeNft)
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
	if err != nil || res.Pending != nil {
		t.Fatalf("Propose = %+v, %v", res, err)
	}
	if len(h.r.applied) != 1 || !strings.Contains(h.r.applied[0], `tcp dport 443 accept comment "svc:11111111-1111-1111-1111-111111111111"`) {
		t.Fatalf("applied = %v", h.r.applied)
	}
	if commits != 1 || len(h.persisted) != 1 || h.persisted[0] != h.r.applied[0] {
		t.Fatal("an immediate change must be stored once and persisted for boot")
	}
}

func TestProposeWithConfirmStoresOnlyAfterConfirm(t *testing.T) {
	h := newHarness(ModeNft)
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), true, nil)
	if err != nil || res.Pending == nil {
		t.Fatalf("Propose = %+v, %v", res, err)
	}
	if commits != 0 || len(h.persisted) != 0 {
		t.Fatal("nothing may be stored before confirmation")
	}
	if err := h.e.Confirm(context.Background(), res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	if commits != 1 || len(h.persisted) != 1 {
		t.Fatal("confirm must store and persist the change")
	}
}

func TestRolledBackChangeIsNeverStored(t *testing.T) {
	h := newHarness(ModeNft)
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.rollback() // nobody confirmed in time

	if err := h.e.Confirm(context.Background(), res.Pending.ID); !errors.Is(err, nft.ErrNoPending) {
		t.Fatalf("confirm after rollback = %v, want ErrNoPending", err)
	}
	if commits != 0 || len(h.persisted) != 0 {
		t.Fatal("a rolled-back change must never reach the database or the boot ruleset")
	}
}

func TestProposeRefusesToBlockTheOperator(t *testing.T) {
	h := newHarness(ModeNft)
	block := Change{Mutate: func(st *State) error {
		st.IPRules = append(st.IPRules, &models.FirewallIPRule{ID: "22222222-2222-2222-2222-222222222222",
			Action: "block", Prefix: "203.0.113.0/24"})
		return nil
	}}
	_, err := h.e.Propose(context.Background(), block, false, []netip.Addr{netip.MustParseAddr("203.0.113.50")})
	if !errors.Is(err, ErrRejected) || len(h.r.applied) != 0 {
		t.Fatalf("blocking the operator must be rejected before anything is applied (err=%v)", err)
	}
}

func TestDesiredConvertsStoredState(t *testing.T) {
	h := newHarness(ModeNft)
	past := engineNow.Add(-time.Minute)
	soon := engineNow.Add(30 * time.Minute)
	h.st.ipRules = []*models.FirewallIPRule{
		{ID: "a1111111-1111-1111-1111-111111111111", Action: "block", Prefix: "198.51.100.9/32", ExpiresAt: &soon},
		{ID: "a2222222-2222-2222-2222-222222222222", Action: "block", Prefix: "203.0.113.7/32", Protocol: "tcp", Ports: "80,443"},
		{ID: "a3333333-3333-3333-3333-333333333333", Action: "allow", Prefix: "192.0.2.0/24"},
		{ID: "a4444444-4444-4444-4444-444444444444", Action: "block", Prefix: "192.0.2.200/32", ExpiresAt: &past},
	}
	h.st.forwards = []*models.FirewallForward{{ID: "f1111111-1111-1111-1111-111111111111", Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.5", TargetPort: 80}}
	h.st.egress = []string{"node-7"}

	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	got := h.r.applied[0]
	for _, want := range []string{
		"elements = { 198.51.100.9 timeout 1800s }",
		`ip saddr 203.0.113.7 tcp dport { 80, 443 } counter drop`,
		`ip saddr 192.0.2.0/24 accept`,
		`dnat ip to 10.20.0.5:80`,
		"elements = { 10.20.0.7 }",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(got, "192.0.2.200") {
		t.Error("expired rules must not be applied")
	}
	if h.expiryIn != 30*time.Minute+time.Second {
		t.Fatalf("reconcile must be scheduled for the next expiry, got %v", h.expiryIn)
	}
}

// An invalid stored row (e.g. imported from iptables) must not block every
// change, but the same mistake in a new change must be rejected.
func TestInvalidStoredRowWarnsButInvalidChangeIsRejected(t *testing.T) {
	h := newHarness(ModeNft)
	h.st.services = []*models.FirewallService{{ID: "b1111111-1111-1111-1111-111111111111",
		Protocol: "tcp", PortFrom: 8443, PortTo: 8443, Sources: []string{"203.0.113.0/24"}}}

	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
	if err != nil {
		t.Fatalf("a stale invalid row must not block a valid change: %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(h.r.applied[0], "tcp dport 443 accept") || strings.Contains(h.r.applied[0], "svc:b1111111") {
		t.Fatalf("warnings=%v\n%s", res.Warnings, h.r.applied[0])
	}

	bad := Change{Mutate: func(st *State) error {
		st.Services = append(st.Services, &models.FirewallService{ID: "b2222222-2222-2222-2222-222222222222",
			Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Sources: []string{}})
		return nil
	}}
	if _, err := h.e.Propose(context.Background(), bad, false, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("opening a reserved admin port publicly must be rejected, got %v", err)
	}
}

func TestShadowCheckDoesNotApply(t *testing.T) {
	h := newHarness(ModeShadow)
	if _, err := h.e.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.r.checked != 1 || len(h.r.applied) != 0 {
		t.Fatal("shadow mode may only run nft -c")
	}
}

func TestImportIptablesRunsOnce(t *testing.T) {
	h := newHarness(ModeNft)
	h.r.iptS = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n-A INPUT -s 198.51.100.9/32 -j DROP\n"
	n, _, err := ImportIptables(context.Background(), h.st, h.r, []uint16{22}, engineNow)
	if err != nil || n != 2 {
		t.Fatalf("import = %d, %v", n, err)
	}
	if n, _, _ := ImportIptables(context.Background(), h.st, h.r, []uint16{22}, engineNow); n != 0 || h.st.imports != 1 {
		t.Fatal("the import must run only once")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeIptables, "NFT": ModeNft, " shadow ": ModeShadow} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("nftables"); err == nil {
		t.Error("unknown modes must be rejected")
	}
}
