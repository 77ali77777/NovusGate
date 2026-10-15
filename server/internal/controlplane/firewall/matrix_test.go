package firewall

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

type matrixSource struct {
	networks []*models.Network
	rules    []*models.VPNFirewallRule
	nodes    map[string]*models.Node
}

func (m matrixSource) ListNetworks(context.Context) ([]*models.Network, error) {
	return m.networks, nil
}
func (m matrixSource) ListVPNFirewallRules(context.Context) ([]*models.VPNFirewallRule, error) {
	return m.rules, nil
}
func (m matrixSource) GetNode(_ context.Context, id string) (*models.Node, error) {
	return m.nodes[id], nil
}

func ptr(s string) *string { return &s }

func vpnRule(name string, over func(r *models.VPNFirewallRule)) *models.VPNFirewallRule {
	r := &models.VPNFirewallRule{ID: name, Name: name, SourceType: "network", DestType: "network", Protocol: "all", Action: "accept", Enabled: true}
	over(r)
	return r
}

func matrixNets() []*models.Network {
	return []*models.Network{
		{ID: "a", Name: "A", CIDR: "10.1.0.0/24", InterfaceName: "wg1", ListenPort: 51821},
		{ID: "b", Name: "B", CIDR: "10.2.0.0/24", InterfaceName: "wg2", ListenPort: 51822},
		{ID: "c", Name: "C", CIDR: "10.3.0.0/24", InterfaceName: "wg3", ListenPort: 51823},
	}
}

func row(m Matrix, from string) []string {
	var out []string
	for _, n := range m.Networks {
		out = append(out, m.Cells[from][n.ID].Verdict)
	}
	return out
}

func buildMatrix(t *testing.T, rules []*models.VPNFirewallRule, nodes map[string]*models.Node, nft bool) Matrix {
	t.Helper()
	m, _, err := PolicyMatrix(context.Background(), matrixSource{networks: matrixNets(), rules: rules, nodes: nodes}, nft)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMatrixDefaults(t *testing.T) {
	if got := row(buildMatrix(t, nil, nil, true), "a"); !reflect.DeepEqual(got, []string{"allow", "deny", "deny"}) {
		t.Fatalf("nft defaults = %v", got)
	}
	if got := row(buildMatrix(t, nil, nil, false), "a"); !reflect.DeepEqual(got, []string{"allow", "allow", "allow"}) {
		t.Fatalf("iptables defaults = %v", got)
	}
}

func TestMatrixFirstWholeRuleDecides(t *testing.T) {
	rules := []*models.VPNFirewallRule{
		vpnRule("a to b", func(r *models.VPNFirewallRule) { r.SourceNetworkID, r.DestNetworkID = ptr("a"), ptr("b") }),
		vpnRule("block all", func(r *models.VPNFirewallRule) { r.SourceType, r.DestType, r.Action = "any", "any", "drop" }),
		vpnRule("disabled", func(r *models.VPNFirewallRule) {
			r.SourceNetworkID, r.DestNetworkID, r.Enabled = ptr("b"), ptr("c"), false
		}),
	}
	m := buildMatrix(t, rules, nil, true)
	if got := row(m, "a"); !reflect.DeepEqual(got, []string{"deny", "allow", "deny"}) {
		t.Fatalf("row a = %v", got)
	}
	if c := m.Cells["a"]["b"]; !reflect.DeepEqual(c.Rules, []string{"a to b"}) {
		t.Fatalf("a->b rules = %v", c.Rules)
	}
	if c := m.Cells["b"]["c"]; c.Verdict != "deny" || !reflect.DeepEqual(c.Rules, []string{"block all"}) {
		t.Fatalf("b->c = %+v", c)
	}
}

// A node rule only touches the node's own network; a custom prefix covering
// a whole network decides for it.
func TestMatrixResolvesNodesAndCustomPrefixes(t *testing.T) {
	nodes := map[string]*models.Node{"c1": {ID: "c1", VirtualIP: net.ParseIP("10.3.0.5")}}
	rules := []*models.VPNFirewallRule{
		vpnRule("node c1 to b", func(r *models.VPNFirewallRule) {
			r.SourceType, r.SourceNodeID, r.DestNetworkID = "node", ptr("c1"), ptr("b")
		}),
	}
	if got := row(buildMatrix(t, rules, nodes, true), "a"); !reflect.DeepEqual(got, []string{"allow", "deny", "deny"}) {
		t.Fatalf("row a with a node rule from C = %v", got)
	}
	if c := buildMatrix(t, rules, nodes, true).Cells["c"]["b"]; c.Verdict != "partial" {
		t.Fatalf("c->b = %+v", c)
	}

	rules = []*models.VPNFirewallRule{
		vpnRule("custom = A", func(r *models.VPNFirewallRule) {
			r.SourceType, r.SourceIP, r.DestNetworkID, r.Action = "custom", "10.1.0.0/24", ptr("b"), "drop"
		}),
		vpnRule("allow all", func(r *models.VPNFirewallRule) { r.SourceType, r.DestType = "any", "any" }),
	}
	m := buildMatrix(t, rules, nodes, true)
	if got := []string{m.Cells["a"]["b"].Verdict, m.Cells["b"]["b"].Verdict, m.Cells["c"]["b"].Verdict}; !reflect.DeepEqual(got, []string{"deny", "allow", "allow"}) {
		t.Fatalf("column b = %v", got)
	}

	// A rule towards an internet address touches no VPN network.
	rules = []*models.VPNFirewallRule{
		vpnRule("no dns", func(r *models.VPNFirewallRule) {
			r.SourceType, r.DestType, r.DestIP, r.Action = "any", "custom", "8.8.8.8", "drop"
		}),
	}
	if got := row(buildMatrix(t, rules, nodes, false), "a"); !reflect.DeepEqual(got, []string{"allow", "allow", "allow"}) {
		t.Fatalf("internet-only rule = %v", got)
	}
}

func TestMatrixScopedRules(t *testing.T) {
	rules := []*models.VPNFirewallRule{
		vpnRule("web only", func(r *models.VPNFirewallRule) {
			r.SourceNetworkID, r.DestNetworkID, r.Protocol, r.Port = ptr("a"), ptr("b"), "tcp", "443"
		}),
		vpnRule("no ssh", func(r *models.VPNFirewallRule) {
			r.SourceNetworkID, r.DestNetworkID, r.Protocol, r.Port, r.Action = ptr("a"), ptr("c"), "tcp", "22", "drop"
		}),
	}
	m := buildMatrix(t, rules, nil, true)
	if c := m.Cells["a"]["b"]; c.Verdict != "partial" {
		t.Fatalf("a->b = %+v", c)
	}
	// a drop that agrees with the default keeps the cell whole
	if c := m.Cells["a"]["c"]; c.Verdict != "deny" || !reflect.DeepEqual(c.Rules, []string{"no ssh"}) {
		t.Fatalf("a->c = %+v", c)
	}
}
