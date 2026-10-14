package rest

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

type fakePeerAdder struct {
	added []string
	fail  map[string]bool
}

func (f *fakePeerAdder) AddPeer(publicKey, allowedIPs string) error {
	if f.fail[publicKey] {
		return errors.New("wg set failed")
	}
	f.added = append(f.added, publicKey+" "+allowedIPs)
	return nil
}

func testNode(name, key, ip string, status models.NodeStatus, expires *time.Time) *models.Node {
	return &models.Node{Name: name, PublicKey: key, VirtualIP: net.ParseIP(ip), Status: status, ExpiresAt: expires}
}

func TestRestorePeersAddsOnlyActiveMissingNodes(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	exact := now

	nodes := []*models.Node{
		testNode("active", "KEY_ACTIVE", "10.99.0.3", models.NodeStatusOnline, nil),
		testNode("pending-future", "KEY_FUTURE", "10.99.0.4", models.NodeStatusPending, &future),
		testNode("live-already", "KEY_LIVE", "10.99.0.5", models.NodeStatusOnline, nil),
		testNode("expired-by-time", "KEY_PAST", "10.99.0.6", models.NodeStatusOnline, &past),
		testNode("expired-by-status", "KEY_DISABLED", "10.99.0.7", models.NodeStatusExpired, nil),
		testNode("no-key", "", "10.99.0.8", models.NodeStatusOnline, nil),
		testNode("no-ip", "KEY_NOIP", "", models.NodeStatusOnline, nil),
		// Same boundary as enrichNode: expired only when now.After(expires_at).
		testNode("expires-exactly-now", "KEY_EXACT", "10.99.0.9", models.NodeStatusOnline, &exact),
	}
	live := map[string]wireguard.PeerStatus{"KEY_LIVE": {PublicKey: "KEY_LIVE"}}

	f := &fakePeerAdder{}
	added, skipped, errs := restorePeers(f, nodes, live, now)

	want := []string{"KEY_ACTIVE 10.99.0.3/32", "KEY_FUTURE 10.99.0.4/32", "KEY_EXACT 10.99.0.9/32"}
	if !reflect.DeepEqual(f.added, want) {
		t.Fatalf("added peers = %v, want %v", f.added, want)
	}
	if added != 3 {
		t.Fatalf("added = %d, want 3", added)
	}
	// live-already, expired-by-time, expired-by-status; no-key and no-ip are never peers.
	if skipped != 3 {
		t.Fatalf("skipped = %d, want 3", skipped)
	}
	if errs == nil || len(errs) != 0 {
		t.Fatalf("errs = %#v, want empty non-nil slice", errs)
	}
}

func TestRestorePeersReportsFailuresAndContinues(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	nodes := []*models.Node{
		testNode("broken", "KEY_BROKEN", "10.99.0.3", models.NodeStatusOnline, nil),
		testNode("fine", "KEY_FINE", "10.99.0.4", models.NodeStatusOnline, nil),
	}
	f := &fakePeerAdder{fail: map[string]bool{"KEY_BROKEN": true}}

	added, _, errs := restorePeers(f, nodes, nil, now)

	if added != 1 || len(errs) != 1 {
		t.Fatalf("added=%d errs=%v, want 1 and 1", added, errs)
	}
	if errs[0] != "failed to add broken: wg set failed" {
		t.Fatalf("errs[0] = %q", errs[0])
	}
}

// fakePC is one interface for node edits; calls records every change.
type fakePC struct {
	peers map[string]wireguard.PeerStatus
	calls []string
}

func (f *fakePC) GetPeers() (map[string]wireguard.PeerStatus, error) { return f.peers, nil }
func (f *fakePC) AddPeer(k, ips string) error {
	f.calls = append(f.calls, "add "+k+" "+ips)
	f.peers[k] = wireguard.PeerStatus{AllowedIPs: ips}
	return nil
}
func (f *fakePC) UpdatePeerAllowedIPs(k, ips string) error {
	f.calls = append(f.calls, "update "+k+" "+ips)
	f.peers[k] = wireguard.PeerStatus{AllowedIPs: ips}
	return nil
}
func (f *fakePC) RemovePeer(k string) error {
	f.calls = append(f.calls, "remove "+k)
	delete(f.peers, k)
	return nil
}

func TestEnsurePeer(t *testing.T) {
	f := &fakePC{peers: map[string]wireguard.PeerStatus{
		"GW":    {AllowedIPs: "192.168.50.0/24"},           // a gateway that lost its /32
		"OTHER": {AllowedIPs: "10.99.0.9/32,10.99.0.7/32"}, // another peer holding 10.99.0.7
	}}
	if err := ensurePeer(f, "GW", "10.99.0.3/32"); err != nil {
		t.Fatal(err)
	}
	if err := ensurePeer(f, "NEW", "10.99.0.4/32"); err != nil {
		t.Fatal(err)
	}
	if err := ensurePeer(f, "TAKER", "10.99.0.7/32"); err == nil {
		t.Fatal("taking another peer's /32 must be refused")
	}
	want := []string{"update GW 192.168.50.0/24,10.99.0.3/32", "add NEW 10.99.0.4/32"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
}

func TestRestorePeersSkipsAddressesOfOtherPeers(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	nodes := []*models.Node{testNode("dup", "KEY_DUP", "10.99.0.7", models.NodeStatusOnline, nil)}
	live := map[string]wireguard.PeerStatus{"OTHER": {AllowedIPs: "10.99.0.7/32"}}
	f := &fakePeerAdder{}
	added, _, errs := restorePeers(f, nodes, live, now)
	if added != 0 || len(errs) != 1 || len(f.added) != 0 {
		t.Fatalf("added=%d errs=%v calls=%v, want the conflict reported and nothing added", added, errs, f.added)
	}
}

// PUT /nodes through the handler: reactivating adds the peer (keeping a
// live peer's routes), expiring removes it.
func TestUpdateNodeMovesThePeer(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	f := &fakePC{peers: map[string]wireguard.PeerStatus{}}
	orig := nodePeerControl
	t.Cleanup(func() { nodePeerControl = orig })
	nodePeerControl = func(*Server, string) peerControl { return f }
	node := seed.node
	if rec := callAs(t, s, "PUT", "/api/v1/nodes/"+node.ID, `{"status":"expired"}`, true); rec.Code != 200 {
		t.Fatalf("expire = %d %s", rec.Code, rec.Body)
	}
	f.peers[node.PublicKey] = wireguard.PeerStatus{AllowedIPs: "192.168.60.0/24"} // a gateway route left behind
	if rec := callAs(t, s, "PUT", "/api/v1/nodes/"+node.ID, `{"status":"online"}`, true); rec.Code != 200 {
		t.Fatalf("reactivate = %d %s", rec.Code, rec.Body)
	}
	want := []string{"remove " + node.PublicKey, "update " + node.PublicKey + " 192.168.60.0/24," + node.VirtualIP.String() + "/32"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
}

// A broader route (an exit gateway's 0.0.0.0/0, a site's subnet) does not
// own a node's /32: WireGuard routes the /32 by longest prefix and only an
// identical prefix would move between peers.
func TestBroadRoutesDoNotBlockNodePeers(t *testing.T) {
	f := &fakePC{peers: map[string]wireguard.PeerStatus{"EXIT": {AllowedIPs: "0.0.0.0/0"}, "SITE": {AllowedIPs: "10.99.0.0/24"}}}
	if err := ensurePeer(f, "NODE", "10.99.0.5/32"); err != nil {
		t.Fatalf("a /0 or /24 elsewhere must not block a /32: %v", err)
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	a := &fakePeerAdder{}
	added, _, errs := restorePeers(a, []*models.Node{testNode("n", "KEY_N", "10.99.0.6", models.NodeStatusOnline, nil)}, f.peers, now)
	if added != 1 || len(errs) != 0 {
		t.Fatalf("added=%d errs=%v, want the node restored", added, errs)
	}
}
