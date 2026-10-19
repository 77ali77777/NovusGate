package firewall

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// VLAN plan M3: "who can reach whom" for any two devices, networks or
// groups, both ways, with the same evaluation as the policy matrix.

func checkSource(rules ...*models.VPNFirewallRule) groupSource {
	nodes := map[string]*models.Node{
		"pc1": {ID: "pc1", Name: "pc1", NetworkID: "a", VirtualIP: net.ParseIP("10.1.0.5")},
		"pc2": {ID: "pc2", Name: "pc2", NetworkID: "a", VirtualIP: net.ParseIP("10.1.0.6")},
		"srv": {ID: "srv", Name: "srv", NetworkID: "b", VirtualIP: net.ParseIP("10.2.0.7")},
	}
	return groupSource{
		matrixSource: matrixSource{networks: matrixNets(), nodes: nodes, rules: rules},
		groups: []*models.NodeGroup{
			{ID: "staff", Name: "staff", Members: []models.NodeGroupMember{{NodeID: "pc1", VirtualIP: "10.1.0.5"}, {NodeID: "pc2", VirtualIP: "10.1.0.6"}}},
			{ID: "admins", Name: "admins", Members: []models.NodeGroupMember{{NodeID: "pc1", VirtualIP: "10.1.0.5"}}},
			{ID: "empty", Name: "empty"},
		},
	}
}

func check(t *testing.T, src Source, from, to Endpoint) AccessResult {
	t.Helper()
	res, _, err := AccessCheck(context.Background(), src, from, to)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAccessCheckDefaults(t *testing.T) {
	src := checkSource()
	res := check(t, src, Endpoint{"node", "pc1"}, Endpoint{"node", "pc2"})
	if res.Forward.Verdict != "allow" || res.Forward.ReasonKey != "same_network" || res.Reverse.Verdict != "allow" {
		t.Fatalf("same network: %+v", res)
	}
	res = check(t, src, Endpoint{"node", "pc1"}, Endpoint{"node", "srv"})
	if res.Forward.Verdict != "deny" || res.Forward.ReasonKey != "isolated" || res.Reverse.Verdict != "deny" {
		t.Fatalf("other network: %+v", res)
	}
	if res.From.Name != "pc1" || res.To.Name != "srv" || res.To.Addresses[0] != "10.2.0.7/32" {
		t.Fatalf("names: %+v %+v", res.From, res.To)
	}
	// A device's own network: same network.
	if res = check(t, src, Endpoint{"network", "a"}, Endpoint{"node", "pc1"}); res.Forward.Verdict != "allow" {
		t.Fatalf("own network: %+v", res)
	}
}

func TestAccessCheckRulesAndDirection(t *testing.T) {
	rdp := vpnRule("rdp", func(r *models.VPNFirewallRule) {
		r.SourceType, r.SourceNodeID, r.DestType, r.DestNodeID = "node", ptr("pc1"), "node", ptr("srv")
		r.Protocol, r.Port = "tcp", "3389"
	})
	res := check(t, checkSource(rdp), Endpoint{"node", "pc1"}, Endpoint{"node", "srv"})
	if res.Forward.Verdict != "partial" || res.Reverse.Verdict != "deny" || len(res.Forward.Rules) != 1 {
		t.Fatalf("one-way RDP: %+v", res)
	}
	all := vpnRule("staff and b", func(r *models.VPNFirewallRule) {
		r.SourceType, r.SourceGroupID, r.DestNetworkID, r.Bidirectional = "group", ptr("staff"), ptr("b"), true
	})
	res = check(t, checkSource(all), Endpoint{"node", "srv"}, Endpoint{"node", "pc2"})
	if res.Forward.Verdict != "allow" || res.Forward.Rule != "staff and b" || res.Reverse.Verdict != "allow" {
		t.Fatalf("mutual group rule, member by member: %+v", res)
	}
	// Admins is part of staff: allowed. Network a holds more than staff: partial.
	if res = check(t, checkSource(all), Endpoint{"group", "admins"}, Endpoint{"network", "b"}); res.Forward.Verdict != "allow" {
		t.Fatalf("group inside the rule's group: %+v", res)
	}
	only := vpnRule("admins to b", func(r *models.VPNFirewallRule) {
		r.SourceType, r.SourceGroupID, r.DestNetworkID = "group", ptr("admins"), ptr("b")
	})
	res = check(t, checkSource(only), Endpoint{"group", "staff"}, Endpoint{"network", "b"})
	if res.Forward.Verdict != "partial" || res.Forward.ReasonKey != "mixed" {
		t.Fatalf("members differ: %+v", res)
	}
}

func TestAccessCheckEmptyAndUnknown(t *testing.T) {
	src := checkSource()
	if res := check(t, src, Endpoint{"group", "empty"}, Endpoint{"network", "b"}); res.Forward.ReasonKey != "empty" || res.Forward.Verdict != "deny" {
		t.Fatalf("empty group: %+v", res)
	}
	for _, e := range []Endpoint{{"node", "nope"}, {"network", "nope"}, {"group", "nope"}, {"custom", "x"}} {
		if _, _, err := AccessCheck(context.Background(), src, e, Endpoint{"network", "a"}); !errors.Is(err, ErrEndpoint) {
			t.Errorf("%+v: err = %v", e, err)
		}
	}
}
