package store

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestFirewallHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM fw_history"); err != nil {
		t.Fatal(err)
	}
	if has, err := s.HasFirewallHistory(ctx); err != nil || has {
		t.Fatalf("has = %v %v", has, err)
	}
	user := &models.User{Username: "history-user", PasswordHash: "x"}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteUser(context.Background(), user.ID) })

	base := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	for i := 0; i < historyKeep+3; i++ {
		e := &models.FirewallHistoryEntry{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", i), CreatedAt: base.Add(time.Duration(i) * time.Minute),
			Action: fmt.Sprintf("change %d", i), State: []byte(fmt.Sprintf(`{"n":%d}`, i))}
		if i == historyKeep+2 {
			e.UserID = user.ID
		}
		if err := s.InsertFirewallHistory(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// Only the newest historyKeep entries are kept.
	var n int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM fw_history").Scan(&n)
	if n != historyKeep {
		t.Fatalf("kept %d entries", n)
	}
	list, err := s.ListFirewallHistory(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Action != fmt.Sprintf("change %d", historyKeep+2) || list[0].Username != "history-user" ||
		string(list[0].State) != fmt.Sprintf(`{"n": %d}`, historyKeep+2) || list[1].Username != "" {
		t.Fatalf("list = %+v / %s", list[0], list[0].State)
	}
	got, err := s.GetFirewallHistory(ctx, list[1].ID)
	if err != nil || got.Action != list[1].Action || !got.CreatedAt.Equal(list[1].CreatedAt) {
		t.Fatalf("get = %+v %v", got, err)
	}
	if got, err := s.GetFirewallHistory(ctx, "00000000-0000-0000-0000-000000000000"); err != nil || got != nil {
		t.Fatalf("pruned entry = %+v %v", got, err)
	}
}

// ReplaceFirewallState swaps all four parts in one transaction; egress for
// a node that no longer exists is skipped.
func TestReplaceFirewallState(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ResetFirewallHostRules(ctx); err != nil {
		t.Fatal(err)
	}
	s.db.ExecContext(ctx, "DELETE FROM fw_forwards")
	s.db.ExecContext(ctx, "DELETE FROM fw_egress")
	netw := &models.Network{Name: "replace-net", CIDR: "10.78.0.0/24", InterfaceName: "wg78", ListenPort: 51878}
	if err := s.CreateNetwork(ctx, netw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), netw.ID) })
	node := &models.Node{NetworkID: netw.ID, Name: "replace-node", VirtualIP: net.ParseIP("10.78.0.2"),
		PublicKey: "REPLACEKEY00000000000000000000000000000000=", Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := s.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallService(ctx, &models.FirewallService{Protocol: "tcp", PortFrom: 1, PortTo: 1}); err != nil {
		t.Fatal(err)
	}

	svc := &models.FirewallService{ID: "11111111-0000-0000-0000-000000000001", Protocol: "udp", PortFrom: 53, PortTo: 53, Sources: []string{"10.0.0.0/8"}, Comment: "dns"}
	rule := &models.FirewallIPRule{ID: "11111111-0000-0000-0000-000000000002", Action: "block", Prefix: "198.51.100.0/24", Origin: "fail2ban"}
	fwd := &models.FirewallForward{ID: "11111111-0000-0000-0000-000000000003", Protocol: "tcp", PublicPort: 8081, TargetIP: "10.78.0.2", TargetPort: 80}
	gone := "11111111-0000-0000-0000-0000000000ff"
	if err := s.ReplaceFirewallState(ctx, []*models.FirewallService{svc}, []*models.FirewallIPRule{rule},
		[]*models.FirewallForward{fwd}, []string{node.ID, gone}); err != nil {
		t.Fatal(err)
	}
	svcs, _ := s.ListFirewallServices(ctx)
	rules, _ := s.ListFirewallIPRules(ctx)
	fwds, _ := s.ListFirewallForwards(ctx)
	egress, _ := s.ListEgressNodeIDs(ctx)
	if len(svcs) != 1 || svcs[0].ID != svc.ID || svcs[0].Comment != "dns" || len(svcs[0].Sources) != 1 ||
		len(rules) != 1 || rules[0].Origin != "fail2ban" || len(fwds) != 1 || fwds[0].TargetIP != "10.78.0.2" ||
		len(egress) != 1 || egress[0] != node.ID {
		t.Fatalf("after replace: %+v %+v %+v %v", svcs, rules, fwds, egress)
	}
}
