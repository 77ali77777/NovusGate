package store

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// tunnelNet creates a network and two nodes in it for the tunnel tests.
func tunnelNet(t *testing.T, s *Store, name, cidr string, port int) (*models.Network, *models.Node, *models.Node) {
	t.Helper()
	ctx := context.Background()
	iface := fmt.Sprintf("wgt%d", port)
	s.db.ExecContext(ctx, `DELETE FROM networks WHERE name = $1 OR listen_port = $2 OR interface_name = $3`, name, port, iface)
	n := &models.Network{Name: name, CIDR: cidr, ListenPort: port, InterfaceName: iface}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	a := &models.Node{NetworkID: n.ID, Name: "a", VirtualIP: []byte{10, 81, 0, 2}, PublicKey: name + "-A"}
	b := &models.Node{NetworkID: n.ID, Name: "b", VirtualIP: []byte{10, 81, 0, 3}, PublicKey: name + "-B"}
	for _, node := range []*models.Node{a, b} {
		if err := s.CreateNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	return n, a, b
}

func egressHas(t *testing.T, s *Store, id string) bool {
	t.Helper()
	ids, err := s.ListEgressNodeIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return slices.Contains(ids, id)
}

// A new network routes the VPN networks only; nodes follow their network.
func TestNetworkTunnelModeDefaultsToSplit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n, a, _ := tunnelNet(t, s, "tunnel-default", "10.81.0.0/24", 52901)
	got, err := s.GetNetwork(ctx, n.ID)
	if err != nil || got.TunnelMode != models.TunnelSplit {
		t.Fatalf("tunnel mode = %q, %v; want split", got.TunnelMode, err)
	}
	node, _ := s.GetNode(ctx, a.ID)
	if node.TunnelOverride != "" {
		t.Fatalf("override = %q; want none (follow the network)", node.TunnelOverride)
	}
	if egressHas(t, s, a.ID) {
		t.Fatal("a split network's node must not use the hub as internet exit")
	}
}

// The internet exit set is every node whose override, or else whose
// network, says full.
func TestEgressFollowsNetworkAndOverride(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n, a, b := tunnelNet(t, s, "tunnel-follow", "10.81.0.0/24", 52902)
	if found, err := s.SetNetworkTunnelMode(ctx, n.ID, models.TunnelFull); err != nil || !found {
		t.Fatalf("SetNetworkTunnelMode = %v, %v", found, err)
	}
	if !egressHas(t, s, a.ID) || !egressHas(t, s, b.ID) {
		t.Fatal("nodes of a full-tunnel network use the hub as internet exit")
	}
	if err := s.SetNodeTunnelOverride(ctx, b.ID, models.TunnelSplit); err != nil {
		t.Fatal(err)
	}
	if egressHas(t, s, b.ID) || !egressHas(t, s, a.ID) {
		t.Fatal("a split override keeps one node out of its full network's exit")
	}
	if _, err := s.SetNetworkTunnelMode(ctx, n.ID, models.TunnelSplit); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeTunnelOverride(ctx, a.ID, models.TunnelFull); err != nil {
		t.Fatal(err)
	}
	if !egressHas(t, s, a.ID) || egressHas(t, s, b.ID) {
		t.Fatal("a full override gives one node of a split network the exit")
	}
	if err := s.SetNodeTunnelOverride(ctx, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	node, _ := s.GetNode(ctx, a.ID)
	if node.TunnelOverride != "" || egressHas(t, s, a.ID) {
		t.Fatalf("clearing the override follows the network again (override %q)", node.TunnelOverride)
	}
	if found, _ := s.SetNetworkTunnelMode(ctx, "00000000-0000-0000-0000-0000000000aa", models.TunnelFull); found {
		t.Fatal("a missing network must be reported")
	}
}

// The legacy egress toggle (PUT/DELETE /firewall/v2/egress) maps onto the
// override: on = full, off = whatever keeps the node out (split in a full
// network, none in a split one).
func TestSetNodeEgressMapsToOverride(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n, a, _ := tunnelNet(t, s, "tunnel-legacy", "10.81.0.0/24", 52903)
	if err := s.SetNodeEgress(ctx, a.ID, true); err != nil || !egressHas(t, s, a.ID) {
		t.Fatalf("egress on: %v", err)
	}
	if err := s.SetNodeEgress(ctx, a.ID, false); err != nil || egressHas(t, s, a.ID) {
		t.Fatalf("egress off: %v", err)
	}
	if node, _ := s.GetNode(ctx, a.ID); node.TunnelOverride != "" {
		t.Fatalf("off in a split network leaves no override, got %q", node.TunnelOverride)
	}
	s.SetNetworkTunnelMode(ctx, n.ID, models.TunnelFull)
	if err := s.SetNodeEgress(ctx, a.ID, false); err != nil || egressHas(t, s, a.ID) {
		t.Fatalf("egress off in a full network: %v", err)
	}
}

// History restore sets exactly the stored exit set, changing only the nodes
// that differ, so overrides that already agree stay as they are.
func TestReplaceFirewallStateRestoresEgressSet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n, a, b := tunnelNet(t, s, "tunnel-restore", "10.81.0.0/24", 52904)
	s.SetNetworkTunnelMode(ctx, n.ID, models.TunnelFull)
	s.SetNodeTunnelOverride(ctx, a.ID, models.TunnelFull) // agrees with the snapshot: kept
	if err := s.ReplaceFirewallState(ctx, nil, nil, nil, []string{a.ID}); err != nil {
		t.Fatal(err)
	}
	if !egressHas(t, s, a.ID) || egressHas(t, s, b.ID) {
		t.Fatal("the restored exit set must be exactly the snapshot's")
	}
	if node, _ := s.GetNode(ctx, a.ID); node.TunnelOverride != models.TunnelFull {
		t.Fatalf("an override that agrees must stay, got %q", node.TunnelOverride)
	}
	if node, _ := s.GetNode(ctx, b.ID); node.TunnelOverride != models.TunnelSplit {
		t.Fatalf("b left the exit by a split override, got %q", node.TunnelOverride)
	}
}

// Migration 020 turns the old per-node egress rows into full overrides; its
// rollback writes the effective exit set back into fw_egress.
func TestTunnelMigrationRollbackKeepsExitSet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n, a, b := tunnelNet(t, s, "tunnel-down", "10.81.0.0/24", 52905)
	s.SetNetworkTunnelMode(ctx, n.ID, models.TunnelFull)
	s.SetNodeTunnelOverride(ctx, b.ID, models.TunnelSplit)
	down, err := os.ReadFile("migrations_rollback/020_tunnel_mode.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("migrations_sql/020_tunnel_mode.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var rows []string
	r, err := s.db.QueryContext(ctx, `SELECT node_id::text FROM fw_egress WHERE node_id = ANY($1::uuid[])`, "{"+a.ID+","+b.ID+"}")
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var id string
		r.Scan(&id)
		rows = append(rows, id)
	}
	r.Close()
	// Up again (restores the schema the other tests use).
	if _, err := s.db.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("up: %v", err)
	}
	s.db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ('020_tunnel_mode.sql') ON CONFLICT DO NOTHING`)
	if len(rows) != 1 || rows[0] != a.ID {
		t.Fatalf("fw_egress after rollback = %v, want only %s", rows, a.ID)
	}
	if !egressHas(t, s, a.ID) || egressHas(t, s, b.ID) {
		t.Fatal("up again: the fw_egress rows become full overrides")
	}
}
