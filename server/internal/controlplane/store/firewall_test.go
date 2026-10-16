package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// newTestStore connects to TEST_DATABASE_URL (a disposable database), runs
// all migrations and empties the firewall tables. Skips without it.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run database tests (scripts/test-with-postgres.sh)")
	}
	s, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"fw_services", "fw_ip_rules", "fw_forwards", "fw_meta"} {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	// No node uses the hub as internet exit (the exit set comes from these).
	for _, q := range []string{`UPDATE nodes SET tunnel_override = NULL`, `UPDATE networks SET tunnel_mode = 'split'`} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestFirewallServicesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	svc := &models.FirewallService{Protocol: "tcp", PortFrom: 8000, PortTo: 8100,
		Sources: []string{"203.0.113.0/24", "2001:db8::/32"}, Interface: "eth0", Comment: "builds"}
	if err := s.CreateFirewallService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallService(ctx, &models.FirewallService{Protocol: "udp", PortFrom: 53, PortTo: 53}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListFirewallServices(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if got[0].ID != svc.ID || len(got[0].Sources) != 2 || got[0].Interface != "eth0" || got[0].Comment != "builds" {
		t.Fatalf("round trip lost data: %+v", got[0])
	}
	if got[1].Sources == nil || len(got[1].Sources) != 0 {
		t.Fatalf("no sources must read back as an empty list, got %#v", got[1].Sources)
	}
	if err := s.CreateFirewallService(ctx, &models.FirewallService{Protocol: "tcp", PortFrom: 90, PortTo: 80}); err == nil {
		t.Fatal("the schema must reject an inverted port range")
	}
	if err := s.DeleteFirewallService(ctx, svc.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFirewallServices(ctx); len(got) != 1 {
		t.Fatalf("delete failed: %v", got)
	}
}

func TestFirewallIPRulesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := s.CreateFirewallIPRule(ctx, &models.FirewallIPRule{Action: "block", Prefix: "203.0.113.7/32",
		Protocol: "tcp", Ports: "80,443", ExpiresAt: &in, Origin: "fail2ban"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallIPRule(ctx, &models.FirewallIPRule{Action: "allow", Prefix: "2001:db8::/48"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListFirewallIPRules(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if got[0].Prefix != "203.0.113.7/32" || got[0].Ports != "80,443" || got[0].Origin != "fail2ban" ||
		got[0].ExpiresAt == nil || !got[0].ExpiresAt.Equal(in) {
		t.Fatalf("block lost data: %+v", got[0])
	}
	if got[1].Origin != "panel" || got[1].ExpiresAt != nil || got[1].Protocol != "" {
		t.Fatalf("allow defaults wrong: %+v", got[1])
	}
	if err := s.CreateFirewallIPRule(ctx, &models.FirewallIPRule{Action: "block", Prefix: "10.0.0.5/24"}); err == nil {
		t.Fatal("the schema must reject a prefix with host bits set")
	}
	if err := s.ResetFirewallHostRules(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFirewallIPRules(ctx); len(got) != 0 {
		t.Fatalf("reset left %v", got)
	}
}

func TestFirewallForwardsEgressAndMeta(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	f := &models.FirewallForward{Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.5", TargetPort: 80}
	if err := s.CreateFirewallForward(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallForward(ctx, &models.FirewallForward{Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.6", TargetPort: 80}); err == nil {
		t.Fatal("two forwards on the same public port must be rejected")
	}
	got, err := s.ListFirewallForwards(ctx)
	if err != nil || len(got) != 1 || got[0].TargetIP != "10.20.0.5" {
		t.Fatalf("forwards = %v, %v", got, err)
	}

	// Egress rows reference nodes; create a network and node to point at.
	var netID, nodeID string
	if err := s.db.QueryRowContext(ctx, `INSERT INTO networks (name, cidr) VALUES ('fw-test', '10.77.0.0/24')
		ON CONFLICT (name) DO UPDATE SET cidr = EXCLUDED.cidr RETURNING id`).Scan(&netID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `INSERT INTO nodes (network_id, name, virtual_ip, public_key)
		VALUES ($1, 'fw-node', '10.77.0.9', 'KEY') ON CONFLICT (network_id, name) DO UPDATE SET public_key = 'KEY' RETURNING id`, netID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeEgress(ctx, nodeID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeEgress(ctx, nodeID, true); err != nil {
		t.Fatal("enabling twice must be idempotent")
	}
	if ids, _ := s.ListEgressNodeIDs(ctx); len(ids) != 1 || ids[0] != nodeID {
		t.Fatalf("egress = %v", ids)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.ListEgressNodeIDs(ctx); len(ids) != 0 {
		t.Fatal("deleting a node must remove its egress permission")
	}

	if _, ok, err := s.GetFirewallMeta(ctx, "iptables_imported"); err != nil || ok {
		t.Fatalf("missing meta must report ok=false, got %v %v", ok, err)
	}
	if err := s.SetFirewallMeta(ctx, "iptables_imported", "2026-10-13"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFirewallMeta(ctx, "iptables_imported", "again"); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.GetFirewallMeta(ctx, "iptables_imported"); err != nil || !ok || v != "again" {
		t.Fatalf("meta = %q %v %v", v, ok, err)
	}
}

func TestImportFirewallRulesIsAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	good := []*models.FirewallService{{Protocol: "tcp", PortFrom: 443, PortTo: 443}}
	bad := []*models.FirewallIPRule{{Action: "block", Prefix: "not-a-cidr"}}
	if err := s.ImportFirewallRules(ctx, good, bad, "iptables_imported", "x"); err == nil {
		t.Fatal("an invalid rule must fail the import")
	}
	if got, _ := s.ListFirewallServices(ctx); len(got) != 0 {
		t.Fatal("a failed import must not leave partial rows")
	}
	if _, ok, _ := s.GetFirewallMeta(ctx, "iptables_imported"); ok {
		t.Fatal("a failed import must not set the marker")
	}
	ok := []*models.FirewallIPRule{{Action: "block", Prefix: "198.51.100.9/32"}}
	if err := s.ImportFirewallRules(ctx, good, ok, "iptables_imported", "done"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFirewallIPRules(ctx); len(got) != 1 || got[0].Origin != "import" {
		t.Fatalf("imported rules = %+v", got)
	}
	if v, ok, _ := s.GetFirewallMeta(ctx, "iptables_imported"); !ok || v != "done" {
		t.Fatal("the marker must be set with the rows")
	}
}

func TestCreateFirewallServicesIsAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ok := &models.FirewallService{Protocol: "tcp", PortFrom: 443, PortTo: 443}
	bad := &models.FirewallService{Protocol: "xyz", PortFrom: 1, PortTo: 1} // violates CHECK (protocol IN ('tcp', 'udp'))
	if err := s.CreateFirewallServices(ctx, []*models.FirewallService{ok, bad}); err == nil {
		t.Fatal("an invalid service must fail the whole insert")
	}
	if got, _ := s.ListFirewallServices(ctx); len(got) != 0 {
		t.Fatalf("nothing may be stored after a failed insert, got %d", len(got))
	}
}
