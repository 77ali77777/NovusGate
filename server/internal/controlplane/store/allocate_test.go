package store

import (
	"context"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// B21: allocation skips network, .1 (hub) and .2 as before, and never hands
// out the broadcast address; tiny networks fail cleanly.
func TestAllocateIPNeverReturnsBroadcast(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM networks WHERE name LIKE 'alloc-%'"); err != nil {
		t.Fatal(err)
	}
	n := &models.Network{Name: "alloc-29", CIDR: "10.71.0.0/29", ListenPort: 51971, InterfaceName: "wg171"}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), n.ID) })
	var got []string
	for i := 0; i < 10; i++ {
		ip, err := s.AllocateIP(ctx, n.ID)
		if err != nil {
			break
		}
		got = append(got, ip.String())
		if err := s.CreateNode(ctx, &models.Node{NetworkID: n.ID, Name: "alloc-node-" + ip.String(),
			VirtualIP: ip, PublicKey: strings.Repeat("a", 42) + string(rune('A'+i)) + "=", Labels: map[string]string{}}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(got, ",") != "10.71.0.3,10.71.0.4,10.71.0.5,10.71.0.6" {
		t.Fatalf("/29 allocated %v, want .3-.6 (never .7, the broadcast)", got)
	}
	for _, cidr := range []string{"10.72.0.0/30", "10.73.0.0/31", "10.74.0.0/32"} {
		tiny := &models.Network{Name: "alloc-" + cidr, CIDR: cidr, ListenPort: 51972, InterfaceName: "wg172"}
		if err := s.CreateNetwork(ctx, tiny); err != nil {
			t.Fatal(err)
		}
		if ip, err := s.AllocateIP(ctx, tiny.ID); err == nil {
			t.Errorf("%s: allocated %v, want an error", cidr, ip)
		}
		s.DeleteNetwork(ctx, tiny.ID)
	}
}
