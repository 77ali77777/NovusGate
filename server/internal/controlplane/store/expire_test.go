package store

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestExpireNodesPersistsOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM networks WHERE name = 'expire-net'")
	n := &models.Network{Name: "expire-net", CIDR: "10.81.0.0/24", ListenPort: 51981, InterfaceName: "wg181"}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), n.ID) })
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	mk := func(name, ip string, exp *time.Time) *models.Node {
		node := &models.Node{NetworkID: n.ID, Name: name, VirtualIP: net.ParseIP(ip),
			PublicKey: strings.Repeat(name[:1], 43) + "=", Labels: map[string]string{}, Status: models.NodeStatusOnline, ExpiresAt: exp}
		if err := s.CreateNode(ctx, node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	old := mk("a-old", "10.81.0.3", &past)
	mk("b-new", "10.81.0.4", &future)
	mk("c-none", "10.81.0.5", nil)

	got, err := s.ExpireNodes(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != old.ID || got[0].NetworkID != n.ID || got[0].PublicKey != old.PublicKey || got[0].VirtualIP.String() != "10.81.0.3" {
		t.Fatalf("ExpireNodes = %+v, want only a-old with its key and IP", got)
	}
	stored, _ := s.GetNode(ctx, old.ID)
	if stored.Status != models.NodeStatusExpired {
		t.Fatalf("status = %s, want expired", stored.Status)
	}
	if again, err := s.ExpireNodes(ctx, now); err != nil || len(again) != 0 {
		t.Fatalf("second run = %v, %v; an expired node is reported once", again, err)
	}
}
