package rest

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func groupNodes(t *testing.T, s *Server) (*models.Network, *models.Node, *models.Node) {
	t.Helper()
	ctx := context.Background()
	clearRows(t, "DELETE FROM firewall_rules WHERE source_type = 'group' OR dest_type = 'group'")
	clearTable(t, "node_groups")
	n := &models.Network{Name: "grp-net", CIDR: "10.91.0.0/24", ListenPort: 51891, InterfaceName: "wg91"}
	if err := s.store.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	mk := func(name, ip, key string) *models.Node {
		node := &models.Node{NetworkID: n.ID, Name: name, VirtualIP: net.ParseIP(ip), PublicKey: key,
			Labels: map[string]string{}, Status: models.NodeStatusOnline}
		if err := s.store.CreateNode(ctx, node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	return n, mk("grp-a", "10.91.0.2", "GRPRESTA000000000000000000000000000000000A="), mk("grp-b", "10.91.0.3", "GRPRESTB000000000000000000000000000000000B=")
}

func TestGroupsCRUD(t *testing.T) {
	s, _, _ := newContractServer(t)
	_, a, b := groupNodes(t, s)

	rec := callAs(t, s, "POST", "/api/v1/groups", `{"name":"staff","description":"office"}`, true)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "POST", "/api/v1/groups", rec)
	var g models.NodeGroup
	json.Unmarshal(rec.Body.Bytes(), &g)
	if rec := callAs(t, s, "POST", "/api/v1/groups", `{"name":"staff"}`, true); rec.Code != 409 {
		t.Fatalf("duplicate = %d", rec.Code)
	}
	if rec := callAs(t, s, "POST", "/api/v1/groups", `{"name":""}`, true); rec.Code != 400 {
		t.Fatalf("empty name = %d", rec.Code)
	}
	rec = callAs(t, s, "PUT", "/api/v1/groups/"+g.ID+"/members", `{"node_ids":["`+a.ID+`","`+b.ID+`"]}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "10.91.0.3") {
		t.Fatalf("members = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/groups/{id}/members", rec)
	if rec := callAs(t, s, "PUT", "/api/v1/groups/"+g.ID+"/members", `{"node_ids":["00000000-0000-0000-0000-000000000000"]}`, true); rec.Code != 400 {
		t.Fatalf("unknown node = %d %s", rec.Code, rec.Body)
	}
	rec = callAs(t, s, "PUT", "/api/v1/groups/"+g.ID, `{"name":"staff2","description":"x"}`, true)
	if rec.Code != 200 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/groups/{id}", rec)
	list := callAs(t, s, "GET", "/api/v1/groups", "", true)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "staff2") || !strings.Contains(list.Body.String(), "grp-a") {
		t.Fatalf("list = %d %s", list.Code, list.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/groups", list)

	// A VPN rule naming the group keeps it from being deleted.
	rule := `{"name":"staff out","source_type":"group","source_group_id":"` + g.ID + `","dest_type":"any","protocol":"all","action":"accept","priority":100,"enabled":false}`
	rec = callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", rule, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"source_group_name":"staff2"`) {
		t.Fatalf("group rule = %d %s", rec.Code, rec.Body)
	}
	var r models.VPNFirewallRule
	json.Unmarshal(rec.Body.Bytes(), &r)
	if rec := callAs(t, s, "DELETE", "/api/v1/groups/"+g.ID, "", true); rec.Code != 409 {
		t.Fatalf("delete in use = %d %s", rec.Code, rec.Body)
	}
	callAs(t, s, "DELETE", "/api/v1/firewall/vpn/rules/"+r.ID, "", true)
	if rec := callAs(t, s, "DELETE", "/api/v1/groups/"+g.ID, "", true); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "DELETE", "/api/v1/groups/"+g.ID, "", true); rec.Code != 404 {
		t.Fatalf("delete again = %d", rec.Code)
	}
}

func TestGroupRuleValidation(t *testing.T) {
	s, _, _ := newContractServer(t)
	groupNodes(t, s)
	for _, body := range []string{
		`{"name":"x","source_type":"group","dest_type":"any","protocol":"all","action":"accept"}`,
		`{"name":"x","source_type":"group","source_group_id":"00000000-0000-0000-0000-000000000000","dest_type":"any","protocol":"all","action":"accept"}`,
		`{"name":"x","source_type":"any","dest_type":"group","protocol":"all","action":"accept"}`,
	} {
		if rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", body, true); rec.Code != 400 {
			t.Fatalf("%s = %d %s", body, rec.Code, rec.Body)
		}
	}
}

// iptables mode: a group expands to one rule per member address.
func TestGroupRuleInIptablesChain(t *testing.T) {
	s, _, stub := newContractServer(t)
	_, a, b := groupNodes(t, s)
	g := &models.NodeGroup{Name: "chain-staff"}
	if err := s.store.CreateNodeGroup(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	s.store.SetNodeGroupMembers(context.Background(), g.ID, []string{a.ID, b.ID})
	for _, cmd := range []string{"iptables -F NOVUSGATE-VPN", "iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN", "iptables -L FORWARD -n -v --line-numbers"} {
		stub.out[cmd] = ""
	}
	stub.calls = nil
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules",
		`{"name":"staff drop","source_type":"group","source_group_id":"`+g.ID+`","dest_type":"custom","dest_ip":"8.8.8.8","protocol":"all","action":"drop","priority":100,"enabled":true}`, true)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	calls := strings.Join(stub.calls, "\n")
	for _, ip := range []string{"10.91.0.2/32", "10.91.0.3/32"} {
		if !strings.Contains(calls, "iptables -A NOVUSGATE-VPN -s "+ip+" -d 8.8.8.8/32 -j DROP") {
			t.Errorf("missing rule for %s in\n%s", ip, calls)
		}
	}
}

// An accept rule naming a group widens the AllowedIPs (routes) of the
// networks its members are in, like a node rule does for the node's network.
func TestGroupNetworkCIDRs(t *testing.T) {
	s, _, _ := newContractServer(t)
	n1, a, _ := groupNodes(t, s)
	ctx := context.Background()
	n2 := &models.Network{Name: "grp-net2", CIDR: "10.92.0.0/24", ListenPort: 51892, InterfaceName: "wg92"}
	if err := s.store.CreateNetwork(ctx, n2); err != nil {
		t.Fatal(err)
	}
	c := &models.Node{NetworkID: n2.ID, Name: "grp-c", VirtualIP: net.ParseIP("10.92.0.2"), PublicKey: "GRPRESTC000000000000000000000000000000000C=",
		Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := s.store.CreateNode(ctx, c); err != nil {
		t.Fatal(err)
	}
	g := &models.NodeGroup{Name: "two-nets"}
	s.store.CreateNodeGroup(ctx, g)
	s.store.SetNodeGroupMembers(ctx, g.ID, []string{a.ID, c.ID})
	cidrs := map[string]string{n1.ID: n1.CIDR, n2.ID: n2.CIDR}
	got := s.groupNetworkCIDRs(ctx, &g.ID, cidrs)
	if strings.Join(got, ",") != "10.91.0.0/24,10.92.0.0/24" {
		t.Fatalf("cidrs = %v", got)
	}
	if got := s.groupNetworkCIDRs(ctx, nil, cidrs); len(got) != 0 {
		t.Fatalf("nil group = %v", got)
	}
}
