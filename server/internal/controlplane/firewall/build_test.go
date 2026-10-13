package firewall

import (
	"net"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func strPtr(s string) *string { return &s }

func TestVPNRulesFromModels(t *testing.T) {
	networks := map[string]*models.Network{
		"net-a": {ID: "net-a", Name: "A", CIDR: "10.20.0.0/24", InterfaceName: "wg1"},
		"net-b": {ID: "net-b", Name: "B", CIDR: "10.30.0.0/24", InterfaceName: "wg2"},
	}
	nodes := map[string]*models.Node{
		"node-1": {ID: "node-1", VirtualIP: net.ParseIP("10.30.0.5")},
	}
	rules := []*models.VPNFirewallRule{
		{ID: "r1", Name: "a-to-b-ssh", SourceType: "network", SourceNetworkID: strPtr("net-a"),
			DestType: "node", DestNodeID: strPtr("node-1"), Protocol: "tcp", Port: "22, 8000:8100", Action: "accept", Enabled: true},
		{ID: "r2", Name: "disabled", SourceType: "any", DestType: "any", Protocol: "all", Action: "drop", Enabled: false},
		{ID: "r3", Name: "custom-host", SourceType: "custom", SourceIP: "10.20.0.9", DestType: "network",
			DestNetworkID: strPtr("net-b"), Protocol: "icmp", Action: "accept", Enabled: true},
		{ID: "r4", Name: "dangling", SourceType: "network", SourceNetworkID: strPtr("gone"), DestType: "any",
			Protocol: "all", Action: "accept", Enabled: true},
		{ID: "r5", Name: "bad-port", SourceType: "any", DestType: "any", Protocol: "udp", Port: "53-x", Action: "accept", Enabled: true},
	}

	got, errs := VPNRulesFromModels(rules, networks, nodes)

	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(got), got)
	}
	r1 := got[0]
	if r1.ID != "r1" || r1.Src.String() != "10.20.0.0/24" || r1.Dst.String() != "10.30.0.5/32" ||
		r1.Proto != nft.TCP || len(r1.Ports) != 2 || r1.Ports[1] != (nft.PortRange{From: 8000, To: 8100}) {
		t.Fatalf("unexpected r1: %+v", r1)
	}
	if got[1].Src.String() != "10.20.0.9/32" || got[1].Proto != nft.ICMP {
		t.Fatalf("unexpected r3: %+v", got[1])
	}
	if len(errs) != 2 {
		t.Fatalf("want 2 conversion errors (dangling network, bad port), got %v", errs)
	}
}

func TestNetworksFromModels(t *testing.T) {
	got, errs := NetworksFromModels([]*models.Network{
		{Name: "Admin", CIDR: "10.99.0.1/24", InterfaceName: "wg0", ListenPort: 51820},
		{Name: "Legacy", CIDR: "10.40.0.0/24"},
	})
	if len(got) != 1 || got[0].CIDR.String() != "10.99.0.0/24" || got[0].ListenPort != 51820 {
		t.Fatalf("unexpected networks %+v", got)
	}
	if len(errs) != 1 {
		t.Fatalf("network without interface must be reported, got %v", errs)
	}
}

func TestParsePorts(t *testing.T) {
	for _, bad := range []string{"", "0", "70000", "9000-8000", "a", "80,"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) must fail", bad)
		}
	}
	got, err := ParsePorts("80,443,8000-8100")
	if err != nil || len(got) != 3 || got[2] != (nft.PortRange{From: 8000, To: 8100}) {
		t.Fatalf("ParsePorts = %v, %v", got, err)
	}
}

// One rule or network the engine cannot express must become a warning, never
// a failure of the whole ruleset.
func TestUnsupportedEntriesBecomeWarnings(t *testing.T) {
	networks, nwarn := NetworksFromModels([]*models.Network{
		{Name: "ok", CIDR: "10.20.0.0/24", InterfaceName: "wg1"},
		{Name: "v6", CIDR: "fd00::/64", InterfaceName: "wg2"},
		{Name: "long-iface", CIDR: "10.40.0.0/24", InterfaceName: "wg-name-longer-than-15"},
	})
	if len(networks) != 1 || len(nwarn) != 2 {
		t.Fatalf("networks=%+v warnings=%v", networks, nwarn)
	}

	rules, rwarn := VPNRulesFromModels([]*models.VPNFirewallRule{
		{ID: "v6", Name: "v6-host", SourceType: "custom", SourceIP: "2001:db8::1", DestType: "any",
			Protocol: "all", Action: "accept", Enabled: true},
		{ID: "mapped", Name: "mapped-host", SourceType: "custom", SourceIP: "::ffff:10.20.0.9", DestType: "any",
			Protocol: "all", Action: "accept", Enabled: true},
	}, nil, nil)
	if len(rules) != 1 || len(rwarn) != 1 {
		t.Fatalf("rules=%+v warnings=%v", rules, rwarn)
	}
	if rules[0].Src.String() != "10.20.0.9/32" {
		t.Fatalf("IPv4-mapped address must be unmapped, got %s", rules[0].Src)
	}

	rs := nft.Ruleset{SSHPorts: []uint16{22}, EgressInterface: "eth0", Networks: networks, VPNRules: rules}
	if _, err := nft.Compile(rs, time.Now()); err != nil {
		t.Fatalf("the remaining entries must compile: %v", err)
	}
}
