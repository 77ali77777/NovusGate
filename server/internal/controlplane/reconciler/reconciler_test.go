package reconciler

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func key(c string) string { return strings.Repeat(c, 43) + "=" }

// fakeWG is one interface's peers; calls records every change.
type fakeWG struct {
	mu    sync.Mutex
	peers map[string]wireguard.PeerStatus
	calls []string
	err   error
}

func (f *fakeWG) GetPeers() (map[string]wireguard.PeerStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]wireguard.PeerStatus{}
	for k, v := range f.peers {
		out[k] = v
	}
	return out, nil
}
func (f *fakeWG) set(op, k, ips string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+" "+k[:1]+" "+ips)
	if op == "remove" {
		delete(f.peers, k)
	} else {
		f.peers[k] = wireguard.PeerStatus{PublicKey: k, AllowedIPs: ips}
	}
	return nil
}
func (f *fakeWG) AddPeer(k, ips string) error              { return f.set("add", k, ips) }
func (f *fakeWG) UpdatePeerAllowedIPs(k, ips string) error { return f.set("update", k, ips) }
func (f *fakeWG) RemovePeer(k string) error                { return f.set("remove", k, "") }

type fakeStore struct {
	networks []*models.Network
	nodes    map[string]*models.Node // by ID
	expired  []*models.Node
}

func (s *fakeStore) ListNetworks(context.Context) ([]*models.Network, error) { return s.networks, nil }
func (s *fakeStore) ListNodes(_ context.Context, netID string) ([]*models.Node, error) {
	out := []*models.Node{}
	for _, n := range s.nodes {
		if n.NetworkID == netID {
			c := *n
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (s *fakeStore) GetNode(_ context.Context, id string) (*models.Node, error) {
	if n, ok := s.nodes[id]; ok {
		c := *n
		return &c, nil
	}
	return nil, nil
}
func (s *fakeStore) ExpireNodes(_ context.Context, at time.Time) ([]*models.Node, error) {
	out := []*models.Node{}
	for _, n := range s.nodes {
		if n.ExpiresAt != nil && n.ExpiresAt.Before(at) && n.Status != models.NodeStatusExpired {
			n.Status = models.NodeStatusExpired
			c := *n
			out = append(out, &c)
		}
	}
	return out, nil
}

func node(id, netID, k, ip string, status models.NodeStatus, exp *time.Time) *models.Node {
	return &models.Node{ID: id, NetworkID: netID, Name: "node-" + id, PublicKey: key(k), VirtualIP: net.ParseIP(ip), Status: status, ExpiresAt: exp}
}

// setup: wg1 has a (active, live), b (active, missing), c (expired by time, live),
// d (live with /32 missing from allowed-ips), and an unknown live peer u.
func setup(mode Mode) (*Reconciler, *fakeStore, *fakeWG) {
	past := now.Add(-time.Hour)
	st := &fakeStore{
		networks: []*models.Network{{ID: "n1", Name: "Office", CIDR: "10.20.0.0/24", InterfaceName: "wg1"}},
		nodes: map[string]*models.Node{
			"a": node("a", "n1", "a", "10.20.0.3", models.NodeStatusOnline, nil),
			"b": node("b", "n1", "b", "10.20.0.4", models.NodeStatusOnline, nil),
			"c": node("c", "n1", "c", "10.20.0.5", models.NodeStatusOnline, &past),
			"d": node("d", "n1", "d", "10.20.0.6", models.NodeStatusOnline, nil),
		},
	}
	wg := &fakeWG{peers: map[string]wireguard.PeerStatus{
		key("a"): {AllowedIPs: "10.20.0.3/32"},
		key("c"): {AllowedIPs: "10.20.0.5/32"},
		key("d"): {AllowedIPs: "192.168.50.0/24"}, // a site gateway's LAN route
		key("u"): {AllowedIPs: "10.20.0.99/32"},
	}}
	r := New(mode, st, func(iface string) PeerControl { return wg })
	r.Now = func() time.Time { return now }
	return r, st, wg
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeShadow, "SHADOW": ModeShadow, " enforce ": ModeEnforce, "off": ModeOff} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("on"); err == nil {
		t.Error("unknown modes must be rejected")
	}
}

func TestShadowExpiresButOnlyLogsTheDiff(t *testing.T) {
	r, st, wg := setup(ModeShadow)
	rep := r.RunOnce(context.Background())
	// The expire step runs in shadow too: c is marked expired and its peer removed.
	if st.nodes["c"].Status != models.NodeStatusExpired || strings.Join(rep.Expired, ",") != "node-c" {
		t.Fatalf("expire step: status=%s report=%v", st.nodes["c"].Status, rep.Expired)
	}
	if strings.Join(wg.calls, ";") != "remove c " {
		t.Fatalf("shadow may only remove the expired peer, calls=%v", wg.calls)
	}
	kinds := []string{}
	for _, a := range rep.Actions {
		kinds = append(kinds, a.Kind+":"+a.Node)
	}
	sort.Strings(kinds)
	if strings.Join(kinds, ",") != "add:node-b,update:node-d" {
		t.Fatalf("planned actions = %v", kinds)
	}
	if len(rep.Unknown) != 1 || rep.Unknown[0] != "wg1:"+key("u") || !rep.OK() {
		t.Fatalf("unknown=%v errors=%v", rep.Unknown, rep.Errors)
	}
}

func TestEnforceAppliesTheDiff(t *testing.T) {
	r, _, wg := setup(ModeEnforce)
	r.RunOnce(context.Background())
	got := map[string]string{}
	for k, p := range wg.peers {
		got[k[:1]] = p.AllowedIPs
	}
	if got["b"] != "10.20.0.4/32" {
		t.Errorf("missing peer b must be added, peers=%v", got)
	}
	if _, ok := got["c"]; ok {
		t.Errorf("expired peer c must be gone, peers=%v", got)
	}
	if _, ok := got["u"]; !ok {
		t.Errorf("unknown peer u must never be removed, peers=%v", got)
	}
}

func TestEnforceNeverShrinksAllowedIPs(t *testing.T) {
	r, _, wg := setup(ModeEnforce)
	r.RunOnce(context.Background())
	if ips := wg.peers[key("d")].AllowedIPs; ips != "192.168.50.0/24,10.20.0.6/32" {
		t.Fatalf("d allowed-ips = %q, want the gateway route kept and the /32 added", ips)
	}
}

func TestEnforceRechecksBeforeApplying(t *testing.T) {
	r, st, wg := setup(ModeEnforce)
	// b is deleted after the plan is made (between ListNodes and the apply).
	r.beforeApply = func() { delete(st.nodes, "b") }
	rep := r.RunOnce(context.Background())
	if _, ok := wg.peers[key("b")]; ok {
		t.Fatal("a node deleted before the apply must not get its peer back")
	}
	for _, a := range rep.Actions {
		if a.Node == "node-b" {
			t.Fatalf("a skipped action must not be reported as applied: %+v", rep.Actions)
		}
	}
}

func TestOneBrokenInterfaceDoesNotStopTheOthers(t *testing.T) {
	st := &fakeStore{
		networks: []*models.Network{
			{ID: "n1", CIDR: "10.20.0.0/24", InterfaceName: "wg1"},
			{ID: "n2", CIDR: "10.30.0.0/24", InterfaceName: "wg2"},
		},
		nodes: map[string]*models.Node{"x": node("x", "n2", "x", "10.30.0.3", models.NodeStatusOnline, nil)},
	}
	broken := &fakeWG{err: errors.New("Unable to access interface: No such device")}
	good := &fakeWG{peers: map[string]wireguard.PeerStatus{}}
	r := New(ModeEnforce, st, func(iface string) PeerControl {
		if iface == "wg1" {
			return broken
		}
		return good
	})
	r.Now = func() time.Time { return now }
	rep := r.RunOnce(context.Background())
	if rep.OK() || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "wg1") {
		t.Fatalf("errors = %v, want one for wg1", rep.Errors)
	}
	if _, ok := good.peers[key("x")]; !ok {
		t.Fatal("wg2 must still be reconciled")
	}
}

func TestRunLoopTriggersCoalesceAndStop(t *testing.T) {
	r, _, _ := setup(ModeShadow)
	var mu sync.Mutex
	runs := 0
	r.beforeApply = func() { mu.Lock(); runs++; mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	for i := 0; i < 50; i++ {
		r.Trigger() // must never block, however many arrive
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := runs
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must return after the context is cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	if runs < 1 || runs > 2 {
		t.Fatalf("50 triggers must coalesce into 1-2 runs, got %d", runs)
	}
	if st := r.Status(); st.Time.IsZero() || st.Mode != ModeShadow {
		t.Fatalf("Status after a run = %+v", st)
	}
}
