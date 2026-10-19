package firewall

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/novusgate/novusgate/internal/netctl/nft"
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
	// iptables mode keeps networks apart by default too (NOVUSGATE-VPN).
	if got := row(buildMatrix(t, nil, nil, false), "a"); !reflect.DeepEqual(got, []string{"allow", "deny", "deny"}) {
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
	if got := row(buildMatrix(t, rules, nodes, false), "a"); !reflect.DeepEqual(got, []string{"allow", "deny", "deny"}) {
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

// Each cell says why in a form the panel can translate: reason_key (rule,
// same_network, isolated, iptables_default) and the deciding rule's name.
func TestMatrixReasonKeys(t *testing.T) {
	rules := []*models.VPNFirewallRule{
		vpnRule("a to b", func(r *models.VPNFirewallRule) { r.SourceNetworkID, r.DestNetworkID = ptr("a"), ptr("b") }),
		vpnRule("web c", func(r *models.VPNFirewallRule) {
			r.SourceNetworkID, r.DestNetworkID, r.Protocol, r.Port = ptr("a"), ptr("c"), "tcp", "443"
		}),
	}
	m := buildMatrix(t, rules, nil, true)
	for _, c := range []struct {
		from, to, key, rule string
		partial             bool
	}{
		{"a", "b", "rule", "a to b", false},
		{"a", "a", "same_network", "", false},
		{"b", "c", "isolated", "", false},
		{"a", "c", "isolated", "", true},
	} {
		got := m.Cells[c.from][c.to]
		if got.ReasonKey != c.key || got.Rule != c.rule || (got.Verdict == "partial") != c.partial {
			t.Errorf("%s->%s = %+v", c.from, c.to, got)
		}
	}
	// iptables mode keeps networks apart too (NOVUSGATE-VPN ends with a
	// DROP between networks): the same defaults as nftables.
	ipt := buildMatrix(t, nil, nil, false)
	if c := ipt.Cells["a"]["b"]; c.ReasonKey != "isolated" || c.Verdict != "deny" {
		t.Errorf("iptables mode between networks = %+v, want isolated deny", c)
	}
	if c := ipt.Cells["a"]["a"]; c.ReasonKey != "same_network" || c.Verdict != "allow" {
		t.Errorf("iptables mode inside a network = %+v", c)
	}
}

// groupSource adds node groups to a matrixSource.
type groupSource struct {
	matrixSource
	groups []*models.NodeGroup
}

func (g groupSource) ListNodeGroups(context.Context) ([]*models.NodeGroup, error) {
	return g.groups, nil
}

// A group rule compiles to a set of its members' addresses and, in the
// matrix, touches only the networks its members are in.
func TestGroupRulesBuildAndMatrix(t *testing.T) {
	nodes := map[string]*models.Node{}
	src := groupSource{
		matrixSource: matrixSource{networks: matrixNets(), nodes: nodes, rules: []*models.VPNFirewallRule{
			vpnRule("staff to b", func(r *models.VPNFirewallRule) {
				r.SourceType, r.SourceGroupID, r.DestNetworkID = "group", ptr("g1"), ptr("b")
			}),
			vpnRule("to empty group", func(r *models.VPNFirewallRule) {
				r.SourceType, r.DestType, r.DestGroupID, r.Action = "any", "group", ptr("g2"), "drop"
			}),
		}},
		groups: []*models.NodeGroup{
			{ID: "g1", Name: "staff", Members: []models.NodeGroupMember{{NodeID: "n1", VirtualIP: "10.1.0.5"}, {NodeID: "n2", VirtualIP: "10.1.0.6"}}},
			{ID: "g2", Name: "empty"},
			{ID: "g3", Name: "unused", Members: []models.NodeGroupMember{{NodeID: "n9", VirtualIP: "10.3.0.9"}}},
		},
	}
	rs, warnings, err := BuildRuleset(context.Background(), src, []uint16{22}, "eth0")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("build = %v %v", err, warnings)
	}
	if len(rs.Groups) != 2 || rs.VPNRules[0].SrcSet == "" || rs.VPNRules[1].DstSet == "" {
		t.Fatalf("ruleset groups = %+v rules = %+v", rs.Groups, rs.VPNRules)
	}
	var staff nft.Group
	for _, g := range rs.Groups {
		if g.Name == rs.VPNRules[0].SrcSet {
			staff = g
		}
	}
	if len(staff.Members) != 2 || staff.Members[0].String() != "10.1.0.5" {
		t.Fatalf("staff set = %+v", staff)
	}

	m, _, err := PolicyMatrix(context.Background(), src, true)
	if err != nil {
		t.Fatal(err)
	}
	// members are in A only: A->B partial, C->B untouched (deny by default)
	if a, c := m.Cells["a"]["b"], m.Cells["c"]["b"]; a.Verdict != "partial" || c.Verdict != "deny" || len(c.Rules) != 0 {
		t.Fatalf("a->b %+v c->b %+v", a, c)
	}
	// the empty group touches nothing
	if cell := m.Cells["a"]["a"]; cell.Verdict != "allow" || len(cell.Rules) != 0 {
		t.Fatalf("a->a %+v", cell)
	}
}

type limitMatrixSource struct {
	matrixSource
	limits []models.NodeLimit
}

func (l limitMatrixSource) ListLimitProfiles(context.Context) ([]models.LimitProfile, error) {
	up := 1000
	return []models.LimitProfile{{ID: "p1", Name: "slow", UpKbps: &up, Timezone: "UTC"}}, nil
}
func (l limitMatrixSource) ListNodeLimits(context.Context) ([]models.NodeLimit, error) {
	return l.limits, nil
}

// Limits do not change verdicts; a cell is marked limited when a limited
// node is on either side, and only where nftables enforces limits.
func TestMatrixMarksLimitedCells(t *testing.T) {
	src := limitMatrixSource{matrixSource: matrixSource{networks: matrixNets()},
		limits: []models.NodeLimit{{NodeID: "n1", VirtualIP: "10.1.0.5", ProfileID: "p1"}}}
	m, _, err := PolicyMatrix(context.Background(), src, true)
	if err != nil {
		t.Fatal(err)
	}
	for from, row := range m.Cells {
		for to, c := range row {
			want := from == "a" || to == "a"
			if c.Limited != want {
				t.Errorf("%s->%s limited = %v, want %v", from, to, c.Limited, want)
			}
		}
	}
	if m.Cells["b"]["c"].Verdict != "deny" || m.Cells["a"]["a"].Verdict != "allow" {
		t.Errorf("verdicts changed: %+v", m.Cells)
	}
	m, _, _ = PolicyMatrix(context.Background(), src, false)
	if m.Cells["a"]["b"].Limited {
		t.Error("iptables mode does not enforce limits")
	}
}
