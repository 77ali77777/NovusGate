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
	timers    []scheduled
}

// scheduled is a reconcile the engine asked to run later (expiry or retry).
type scheduled struct {
	d time.Duration
	f func()
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
			h.timers = append(h.timers, scheduled{d, f})
			return func() bool { return true }
		},
	}
	h.e.MarkReady()
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

// A reconcile that cannot be applied (pending confirmation, armed rollback
// timer, detection failure) must be retried with backoff, not dropped.
func TestFailedReconcileIsRetriedWithBackoff(t *testing.T) {
	h := newHarness(ModeNft)
	fail := true
	h.e.Detect = func() (HostInfo, error) {
		if fail {
			return HostInfo{}, errors.New("sshd -T failed")
		}
		return HostInfo{SSHPorts: []uint16{22}, Egress: "eth0"}, nil
	}

	if _, err := h.e.ReconcileOrRetry(context.Background()); err == nil {
		t.Fatal("reconcile must fail while detection fails")
	}
	if len(h.timers) != 1 || h.timers[0].d != retryMin {
		t.Fatalf("a retry must be scheduled after %v, got %+v", retryMin, h.timers)
	}
	if _, err := h.e.ReconcileOrRetry(context.Background()); err == nil || len(h.timers) != 1 {
		t.Fatal("only one retry may be scheduled at a time")
	}

	h.timers[0].f() // still failing: the next retry backs off
	if len(h.timers) != 2 || h.timers[1].d != 2*retryMin {
		t.Fatalf("the retry must back off, got %+v", h.timers)
	}

	fail = false
	h.timers[1].f()
	if len(h.r.applied) != 1 {
		t.Fatal("the retry must apply the stored state once the host is ready")
	}
	fail = true
	h.e.ReconcileOrRetry(context.Background())
	if h.timers[len(h.timers)-1].d != retryMin {
		t.Fatal("a successful apply must reset the backoff")
	}
}

// An expiry that fires while a change waits for confirmation must still be
// applied once the host is free again.
func TestExpiryDuringPendingChangeIsRetried(t *testing.T) {
	h := newHarness(ModeNft)
	soon := engineNow.Add(time.Minute)
	h.st.ipRules = []*models.FirewallIPRule{{ID: "c1111111-1111-1111-1111-111111111111",
		Action: "allow", Prefix: "192.0.2.0/24", ExpiresAt: &soon}}
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	expiry := h.timers[len(h.timers)-1]

	commits := 0
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), true, nil); err != nil {
		t.Fatal(err)
	}
	engineNow = engineNow.Add(2 * time.Minute)
	defer func() { engineNow = engineNow.Add(-2 * time.Minute) }()
	expiry.f() // the host is busy with the pending change
	retry := h.timers[len(h.timers)-1]
	if retry.d != retryMin {
		t.Fatalf("the expiry must be retried, got %+v", h.timers)
	}

	h.rollback() // nobody confirmed
	retry.f()
	if got := h.r.applied[len(h.r.applied)-1]; strings.Contains(got, "192.0.2.0/24") {
		t.Fatal("the expired allow must be removed after the rollback")
	}
}

// Protect guards every apply, including startup, expiry and reconcile, which
// carry no requester address.
func TestProtectGuardsReconcile(t *testing.T) {
	h := newHarness(ModeNft)
	h.e.Protect = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.50")} }
	h.st.ipRules = []*models.FirewallIPRule{{ID: "d1111111-1111-1111-1111-111111111111",
		Action: "block", Prefix: "203.0.113.0/24"}}
	if _, err := h.e.Reconcile(context.Background(), nil); !errors.Is(err, ErrRejected) || len(h.r.applied) != 0 {
		t.Fatalf("a ruleset blocking an admin WireGuard endpoint must not be applied (err=%v)", err)
	}
}

// Blocks are matched before allows, so an allow inside a block has no effect;
// creating that situation is rejected in either order.
func TestAllowInsideBlockIsRejected(t *testing.T) {
	h := newHarness(ModeNft)
	h.st.ipRules = []*models.FirewallIPRule{{ID: "e1111111-1111-1111-1111-111111111111",
		Action: "block", Prefix: "203.0.113.0/24"}}
	allow := Change{Mutate: func(st *State) error {
		st.IPRules = append(st.IPRules, &models.FirewallIPRule{ID: "e2222222-2222-2222-2222-222222222222",
			Action: "allow", Prefix: "203.0.113.5/32"})
		return nil
	}}
	if _, err := h.e.Propose(context.Background(), allow, false, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("an allow inside a block must be rejected, got %v", err)
	}

	h.st.ipRules = []*models.FirewallIPRule{{ID: "e3333333-3333-3333-3333-333333333333",
		Action: "allow", Prefix: "198.51.100.5/32"}}
	block := Change{Mutate: func(st *State) error {
		st.IPRules = append(st.IPRules, &models.FirewallIPRule{ID: "e4444444-4444-4444-4444-444444444444",
			Action: "block", Prefix: "198.51.100.0/24", Protocol: "tcp", Ports: "22"})
		return nil
	}}
	if _, err := h.e.Propose(context.Background(), block, false, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("a block covering an allow must be rejected, got %v", err)
	}

	other := Change{Mutate: func(st *State) error {
		st.IPRules = append(st.IPRules, &models.FirewallIPRule{ID: "e5555555-5555-5555-5555-555555555555",
			Action: "block", Prefix: "198.51.100.0/24", Protocol: "tcp", Ports: "80"})
		return nil
	}}
	h.st.ipRules[0].Protocol, h.st.ipRules[0].Ports = "tcp", "443"
	if _, err := h.e.Propose(context.Background(), other, false, nil); err != nil {
		t.Fatalf("blocks on other ports do not conflict: %v", err)
	}
}

func TestAfterApplyRunsOnlyAfterTheHostChanged(t *testing.T) {
	h := newHarness(ModeNft)
	calls := 0
	h.e.AfterApply = func() { calls++ }
	h.e.Applier.Timer.(*hostTimer).active = true // a rollback from before a restart
	if _, err := h.e.Reconcile(context.Background(), nil); err == nil || calls != 0 {
		t.Fatalf("AfterApply must not run when nothing was applied (err=%v, calls=%d)", err, calls)
	}
	h.e.Applier.Timer.(*hostTimer).active = false
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil || calls != 1 {
		t.Fatalf("AfterApply must run after an apply (err=%v, calls=%d)", err, calls)
	}
}

// iptables matches top-down: an earlier allow wins over a later block that
// covers it, but in nft every block wins. Importing that would cut the
// allowed source off, so the import refuses and changes nothing.
func TestImportRefusesAllowShadowedByLaterBlock(t *testing.T) {
	h := newHarness(ModeNft)
	h.r.iptS = "-A INPUT -s 203.0.113.5/32 -j ACCEPT\n-A INPUT -s 203.0.113.0/24 -j DROP\n"
	if _, _, err := ImportIptables(context.Background(), h.st, h.r, []uint16{22}, engineNow); err == nil || h.st.imports != 0 {
		t.Fatalf("a conflicting import must be refused (err=%v, imports=%d)", err, h.st.imports)
	}

	h.r.iptS = "-A INPUT -s 203.0.113.0/24 -j DROP\n-A INPUT -s 203.0.113.5/32 -j ACCEPT\n" +
		"-A INPUT -s 192.0.2.7/32 -p tcp -m tcp --dport 443 -j ACCEPT\n-A INPUT -s 192.0.2.0/24 -p tcp -m tcp --dport 22 -j DROP\n"
	if _, _, err := ImportIptables(context.Background(), h.st, h.r, []uint16{22}, engineNow); err != nil {
		t.Fatalf("a block before the allow, or on other ports, behaves the same in nft: %v", err)
	}
}

func TestEngineRefusesChangesUntilReady(t *testing.T) {
	h := newHarness(ModeNft)
	h.e = &Engine{Mode: ModeNft, Store: h.st, Applier: h.e.Applier, Now: h.e.Now, Detect: h.e.Detect}
	commits := 0
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Propose before MarkReady = %v, want ErrNotReady", err)
	}
	if len(h.r.applied) != 0 || commits != 0 {
		t.Fatal("nothing may be applied or stored before the engine is ready")
	}
	h.e.MarkReady()
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); err != nil {
		t.Fatal(err)
	}
}

// A request whose client disconnects must still store the live change.
func TestCommitIgnoresRequestCancellation(t *testing.T) {
	h := newHarness(ModeNft)
	ctx, cancel := context.WithCancel(context.Background())
	ch := Change{
		Mutate: func(st *State) error { return nil },
		Commit: func(c context.Context) error { cancel(); return c.Err() },
	}
	if _, err := h.e.Propose(ctx, ch, false, nil); err != nil {
		t.Fatalf("commit must not see the request's cancellation: %v", err)
	}
}

// A change that is live but could not be stored is undone by a reconcile.
func TestFailedCommitSchedulesReconcile(t *testing.T) {
	h := newHarness(ModeNft)
	ch := Change{
		Mutate: func(st *State) error { return nil },
		Commit: func(context.Context) error { return errors.New("db down") },
	}
	if _, err := h.e.Propose(context.Background(), ch, false, nil); err == nil {
		t.Fatal("a failed commit must be reported")
	}
	if len(h.timers) != 1 || h.timers[0].d != retryMin {
		t.Fatalf("a reconcile must restore the stored state, timers=%+v", h.timers)
	}
}

func TestPersistFailureIsAWarning(t *testing.T) {
	h := newHarness(ModeNft)
	h.e.Persist = func(string) error { return errors.New("read-only /etc") }
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
	if err != nil || commits != 1 {
		t.Fatalf("the change is live and stored; Persist failure must not be an error (err=%v)", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Error(), "boot-time ruleset") {
		t.Fatalf("warnings = %v", res.Warnings)
	}
}

// The INPUT hand-over (AfterApply) may only happen once the boot-time ruleset
// is on disk; otherwise a reboot would start with iptables ACCEPT and no
// nftables table.
func TestAfterApplyWaitsForTheBootRuleset(t *testing.T) {
	h := newHarness(ModeNft)
	calls := 0
	h.e.AfterApply = func() { calls++ }
	h.e.Persist = func(string) error { return errors.New("disk full") }
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("no hand-over without a boot-time ruleset")
	}
	h.e.Persist = func(string) error { return nil }
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil || calls != 1 {
		t.Fatalf("hand-over after the ruleset is written (err=%v, calls=%d)", err, calls)
	}
}

// A narrower ban that outlives the block covering it is left out while the
// cover stands and comes back when the cover expires: the engine reconciles
// at the cover's expiry.
func TestNarrowerBanReturnsWhenCoverExpires(t *testing.T) {
	h := newHarness(ModeNft)
	coverEnds, banEnds := engineNow.Add(time.Hour), engineNow.Add(5*time.Hour)
	h.st.ipRules = []*models.FirewallIPRule{
		{ID: "f1111111-1111-1111-1111-111111111111", Action: "block", Prefix: "198.51.100.0/24", ExpiresAt: &coverEnds},
		{ID: "f2222222-2222-2222-2222-222222222222", Action: "block", Prefix: "198.51.100.7/32", ExpiresAt: &banEnds},
	}
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.r.applied[len(h.r.applied)-1], "198.51.100.7") {
		t.Fatal("the covered ban is not rendered while the cover stands")
	}
	next := h.timers[len(h.timers)-1]
	if next.d != time.Hour+time.Second {
		t.Fatalf("the next reconcile must run at the cover's expiry, got %s", next.d)
	}
	orig := engineNow
	engineNow = coverEnds.Add(2 * time.Second)
	defer func() { engineNow = orig }()
	next.f()
	if !strings.Contains(h.r.applied[len(h.r.applied)-1], "198.51.100.7") {
		t.Fatalf("the narrower ban must return once the cover expired:\n%s", h.r.applied[len(h.r.applied)-1])
	}
}

// Before startup marks the engine ready, a reconcile is not retried in the
// background: startup reconciles itself once ready, and retries would only
// log the same failure every few minutes.
func TestNotReadyIsNotRetried(t *testing.T) {
	h := newHarness(ModeNft)
	h.e.ready.Store(false)
	if _, err := h.e.ReconcileOrRetry(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("err = %v, want ErrNotReady", err)
	}
	if len(h.timers) != 0 {
		t.Fatalf("no retry may be scheduled while not ready, got %d", len(h.timers))
	}
}

// A reconcile asked for while a change waits for confirmation (e.g. a node
// created in a full-tunnel network) must still run after the confirm: the
// confirmed state was read when the change was proposed, so it lacks what
// changed meanwhile.
func TestReconcileDuringPendingSurvivesConfirm(t *testing.T) {
	h := newHarness(ModeNft)
	ctx := context.Background()
	commits := 0
	res, err := h.e.Propose(ctx, openPort(h, 443, &commits), true, nil)
	if err != nil || res.Pending == nil {
		t.Fatalf("propose = %+v, %v", res, err)
	}
	if _, err := h.e.ReconcileOrRetry(ctx); err == nil {
		t.Fatal("a reconcile must wait while a change is pending")
	}
	if h.e.stopRetry == nil {
		t.Fatal("the reconcile must be retried")
	}
	if err := h.e.Confirm(ctx, res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	if h.e.stopRetry == nil {
		t.Fatal("the retry must survive the confirm, or the meanwhile change is lost")
	}
	if commits != 1 {
		t.Fatalf("commits = %d", commits)
	}
}
