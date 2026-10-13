package rest

import (
	"net"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// B11: the peer follows the node's activity, whatever the stored status said.
func TestPeerTransition(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	node := func(status models.NodeStatus, exp *time.Time) *models.Node {
		return &models.Node{PublicKey: "k", VirtualIP: net.ParseIP("10.0.0.5"), Status: status, ExpiresAt: exp}
	}
	cases := []struct {
		name          string
		before, after *models.Node
		add, remove   bool
	}{
		// The panel showed it expired (lazy), the DB still says online: extending must re-add.
		{"lazily expired, extended", node(models.NodeStatusOnline, &past), node(models.NodeStatusOnline, &future), true, false},
		{"stored expired, extended", node(models.NodeStatusExpired, &past), node(models.NodeStatusPending, &future), true, false},
		// Re-activating by status while expires_at is still in the past must NOT add the peer.
		{"status reactivated, still past", node(models.NodeStatusExpired, &past), node(models.NodeStatusOnline, &past), false, false},
		{"expired by status", node(models.NodeStatusOnline, nil), node(models.NodeStatusExpired, nil), false, true},
		{"expiry moved into the past", node(models.NodeStatusOnline, &future), node(models.NodeStatusOnline, &past), false, true},
		{"rename only", node(models.NodeStatusOnline, nil), node(models.NodeStatusOnline, nil), false, false},
	}
	for _, c := range cases {
		add, remove := peerTransition(c.before, c.after, now)
		if add != c.add || remove != c.remove {
			t.Errorf("%s: add=%v remove=%v, want add=%v remove=%v", c.name, add, remove, c.add, c.remove)
		}
	}
}
