package store

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestEnrollmentTokens(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM networks WHERE name = 'enroll-net'")
	nw := &models.Network{Name: "enroll-net", CIDR: "10.71.0.0/24", ListenPort: 51871, InterfaceName: "wg71"}
	if err := s.CreateNetwork(ctx, nw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), nw.ID) })
	var nodes []*models.Node
	for i, ip := range []string{"10.71.0.2", "10.71.0.3"} {
		n := &models.Node{NetworkID: nw.ID, Name: "enroll-" + ip, VirtualIP: net.ParseIP(ip),
			PublicKey: strings.Repeat(string(rune('a'+i)), 43) + "=", Labels: map[string]string{}, Status: models.NodeStatusPending}
		if err := s.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n)
	}
	a, b := nodes[0].ID, nodes[1].ID
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	if err := s.CreateEnrollmentToken(ctx, a, "e1", now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeEnrollmentToken(ctx, b, "e1", now); err != nil || ok {
		t.Fatalf("another node's token = %v, %v", ok, err)
	}
	if ok, _ := s.ConsumeEnrollmentToken(ctx, a, "e1", now.Add(16*time.Minute)); ok {
		t.Fatal("an expired token must not be accepted")
	}
	if ok, err := s.ConsumeEnrollmentToken(ctx, a, "e1", now.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("a valid token = %v, %v", ok, err)
	}
	if ok, _ := s.ConsumeEnrollmentToken(ctx, a, "e1", now.Add(time.Minute)); ok {
		t.Fatal("a token must be accepted only once")
	}
	if err := s.CreateEnrollmentToken(ctx, a, "e2", now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNode(ctx, a); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM enrollment_tokens WHERE token_hash = 'e2'").Scan(&n)
	if n != 0 {
		t.Fatal("deleting the node must remove its tokens")
	}
}
