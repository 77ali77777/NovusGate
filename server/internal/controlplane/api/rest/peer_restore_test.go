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
	added, errs := restorePeers(f, nodes, live, now)

	want := []string{"KEY_ACTIVE 10.99.0.3/32", "KEY_FUTURE 10.99.0.4/32", "KEY_EXACT 10.99.0.9/32"}
	if !reflect.DeepEqual(f.added, want) {
		t.Fatalf("added peers = %v, want %v", f.added, want)
	}
	if added != 3 {
		t.Fatalf("added = %d, want 3", added)
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

	added, errs := restorePeers(f, nodes, nil, now)

	if added != 1 || len(errs) != 1 {
		t.Fatalf("added=%d errs=%v, want 1 and 1", added, errs)
	}
	if errs[0] != "failed to add broken: wg set failed" {
		t.Fatalf("errs[0] = %q", errs[0])
	}
}
