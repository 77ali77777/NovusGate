package store

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func groupFixture(t *testing.T, s *Store) (*models.Network, *models.Node, *models.Node) {
	t.Helper()
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM firewall_rules WHERE source_type = 'group' OR dest_type = 'group'")
	s.db.ExecContext(ctx, "DELETE FROM node_groups")
	netw := &models.Network{Name: "groups-net", CIDR: "10.79.0.0/24", InterfaceName: "wg79", ListenPort: 51879}
	if err := s.CreateNetwork(ctx, netw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), netw.ID) })
	mk := func(name, ip, key string) *models.Node {
		n := &models.Node{NetworkID: netw.ID, Name: name, VirtualIP: net.ParseIP(ip), PublicKey: key,
			Labels: map[string]string{}, Status: models.NodeStatusOnline}
		if err := s.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	return netw, mk("g-laptop", "10.79.0.2", "GROUPKEYA000000000000000000000000000000000="),
		mk("g-phone", "10.79.0.3", "GROUPKEYB000000000000000000000000000000000=")
}

func TestNodeGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, a, b := groupFixture(t, s)

	g := &models.NodeGroup{Name: "staff", Description: "office people"}
	if err := s.CreateNodeGroup(ctx, g); err != nil || g.ID == "" {
		t.Fatalf("create = %v %+v", err, g)
	}
	if err := s.CreateNodeGroup(ctx, &models.NodeGroup{Name: "staff"}); !errors.Is(err, ErrGroupNameTaken) {
		t.Fatalf("duplicate name = %v", err)
	}
	if err := s.SetNodeGroupMembers(ctx, g.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeGroupMembers(ctx, g.ID, []string{b.ID}); err != nil { // replaces
		t.Fatal(err)
	}
	groups, err := s.ListNodeGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Members) != 1 || groups[0].Members[0].NodeID != b.ID ||
		groups[0].Members[0].Name != "g-phone" || groups[0].Members[0].VirtualIP != "10.79.0.3" || groups[0].Description != "office people" {
		t.Fatalf("groups = %+v", groups)
	}
	if err := s.SetNodeGroupMembers(ctx, g.ID, []string{"00000000-0000-0000-0000-000000000000"}); err == nil {
		t.Fatal("an unknown node must be refused")
	}

	g.Name, g.Description = "staff2", ""
	if err := s.UpdateNodeGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNodeGroup(ctx, g.ID)
	if err != nil || got.Name != "staff2" || len(got.Members) != 1 {
		t.Fatalf("get = %+v %v", got, err)
	}

	// A VPN rule can name the group; the group cannot be deleted while it does.
	rule := &models.VPNFirewallRule{Name: "staff out", SourceType: "group", SourceGroupID: &g.ID, DestType: "any",
		Protocol: "all", Action: "accept", Priority: 100, Enabled: true}
	if err := s.CreateVPNFirewallRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetVPNFirewallRule(ctx, rule.ID)
	if err != nil || stored.SourceGroupID == nil || *stored.SourceGroupID != g.ID || stored.SourceGroupName != "staff2" {
		t.Fatalf("rule = %+v %v", stored, err)
	}
	if err := s.DeleteNodeGroup(ctx, g.ID); !errors.Is(err, ErrGroupInUse) {
		t.Fatalf("delete in use = %v", err)
	}
	if err := s.DeleteVPNFirewallRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNodeGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetNodeGroup(ctx, g.ID); got != nil {
		t.Fatal("group still there")
	}
	// Deleting a node removes it from its groups.
	g2 := &models.NodeGroup{Name: "phones"}
	s.CreateNodeGroup(ctx, g2)
	s.SetNodeGroupMembers(ctx, g2.ID, []string{b.ID})
	if err := s.DeleteNode(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetNodeGroup(ctx, g2.ID); got == nil || len(got.Members) != 0 {
		t.Fatalf("after node delete = %+v", got)
	}
}
