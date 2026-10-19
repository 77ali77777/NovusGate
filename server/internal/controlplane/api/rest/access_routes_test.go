package rest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// VLAN-style access (plan 2026-10-19, M1): every device's config routes all
// VPN networks, whatever the rules say, so a rule works at once in both
// directions of a connection (replies come back) and no device needs a new
// config when rules change. Only the hub's firewall decides who may reach
// whom; networks are apart by default in both firewall engines.

func configOf(t *testing.T, s *Server, nodeID string) string {
	t.Helper()
	rec := callAs(t, s, "GET", "/api/v1/nodes/"+nodeID+"/config", "", true)
	if rec.Code != 200 {
		t.Fatalf("config = %d %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestConfigRoutesEveryNetwork(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st) // contract-net 10.66.0.0/24 (the node's), contract-zempty 10.68.0.0/24
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 10.66.0.0/24, 10.68.0.0/24\n") {
		t.Fatalf("no rule yet, still every network (own first):\n%s", conf)
	}
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"to lan","source_type":"network","source_network_id":"`+
		seed.network.ID+`","dest_type":"custom","dest_ip":"192.168.50.0/24","protocol":"all","action":"accept","priority":100,"enabled":true}`, true)
	if rec.Code != 201 {
		t.Fatalf("rule = %d %s", rec.Code, rec.Body)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 10.66.0.0/24, 10.68.0.0/24, 192.168.50.0/24\n") {
		t.Fatalf("an address range outside the VPN is routed once a rule names it:\n%s", conf)
	}
	if err := st.SetNodeEgress(context.Background(), seed.node.ID, true); err != nil {
		t.Fatal(err)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0\n") {
		t.Fatalf("full tunnel routes everything:\n%s", conf)
	}
}

// A device whose config no longer matches (never downloaded since this
// version, a new network, a tunnel change) says so in the device list.
func TestConfigOutdatedFlag(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	outdated := func() bool {
		t.Helper()
		var nodes []models.Node
		rec := callAs(t, s, "GET", "/api/v1/networks/"+seed.network.ID+"/nodes", "", true)
		json.Unmarshal(rec.Body.Bytes(), &nodes)
		for _, n := range nodes {
			if n.ID == seed.node.ID {
				return n.ConfigOutdated
			}
		}
		t.Fatalf("node missing: %s", rec.Body)
		return false
	}
	if !outdated() {
		t.Fatal("a config never downloaded by this version is outdated")
	}
	configOf(t, s, seed.node.ID)
	if outdated() {
		t.Fatal("just downloaded: up to date")
	}
	n := &models.Network{Name: "contract-routes-new", CIDR: "10.69.0.0/24", ListenPort: 51869, InterfaceName: "wg69"}
	if err := st.CreateNetwork(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if !outdated() {
		t.Fatal("a new network makes the config outdated")
	}
	if body := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID, "", true).Body.String(); !strings.Contains(body, `"config_outdated":true`) {
		t.Fatalf("the device page says it too: %s", body)
	}
}

// iptables mode keeps networks apart like nftables: inside one network
// everything passes, between networks only what a rule allows.
func TestIptablesKeepsNetworksApart(t *testing.T) {
	s, st, stub := newContractServer(t)
	ctx := context.Background()
	a := &models.Network{Name: "iso-a", CIDR: "10.71.0.0/24", ListenPort: 51871, InterfaceName: "wg71"}
	b := &models.Network{Name: "iso-b", CIDR: "10.72.0.0/24", ListenPort: 51872, InterfaceName: "wg72"}
	for _, n := range []*models.Network{a, b} {
		if err := st.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range []string{"iptables -F NOVUSGATE-VPN", "iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"iptables -A NOVUSGATE-VPN -i wg71 -o wg71 -j RETURN", "iptables -A NOVUSGATE-VPN -i wg72 -o wg72 -j RETURN",
		"iptables -A NOVUSGATE-VPN -i wg+ -o wg+ -j DROP -m comment --comment novusgate-vpn-isolation"} {
		stub.out[cmd] = ""
	}
	stub.out["iptables -L FORWARD -n -v --line-numbers"] = "Chain FORWARD (policy DROP)\nnum pkts bytes target prot opt in out source destination\n"
	stub.calls = nil
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"a to b","source_type":"network","source_network_id":"`+
		a.ID+`","dest_type":"network","dest_network_id":"`+b.ID+`","protocol":"all","action":"accept","priority":100,"enabled":true}`, true)
	if rec.Code != 201 {
		t.Fatalf("rule = %d %s", rec.Code, rec.Body)
	}
	calls := strings.Join(stub.calls, "\n")
	accept := strings.Index(calls, "-s 10.71.0.0/24 -d 10.72.0.0/24 -j ACCEPT")
	sameA := strings.Index(calls, "iptables -A NOVUSGATE-VPN -i wg71 -o wg71 -j RETURN")
	sameB := strings.Index(calls, "iptables -A NOVUSGATE-VPN -i wg72 -o wg72 -j RETURN")
	drop := strings.Index(calls, "iptables -A NOVUSGATE-VPN -i wg+ -o wg+ -j DROP -m comment --comment novusgate-vpn-isolation")
	if accept < 0 || sameA < 0 || sameB < 0 || drop < 0 || drop < accept || drop < sameA || drop < sameB {
		t.Fatalf("rules, then same-network RETURNs, then the default DROP:\n%s", calls)
	}
}

// A mutual rule is stored as such and applied both ways in iptables mode.
func TestMutualRuleInIptablesMode(t *testing.T) {
	s, st, stub := newContractServer(t)
	ctx := context.Background()
	a := &models.Network{Name: "mut-a", CIDR: "10.73.0.0/24", ListenPort: 51873, InterfaceName: "wg73"}
	b := &models.Network{Name: "mut-b", CIDR: "10.74.0.0/24", ListenPort: 51874, InterfaceName: "wg74"}
	for _, n := range []*models.Network{a, b} {
		if err := st.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range []string{"iptables -F NOVUSGATE-VPN", "iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"iptables -A NOVUSGATE-VPN -i wg73 -o wg73 -j RETURN", "iptables -A NOVUSGATE-VPN -i wg74 -o wg74 -j RETURN",
		"iptables -A NOVUSGATE-VPN -i wg+ -o wg+ -j DROP -m comment --comment novusgate-vpn-isolation"} {
		stub.out[cmd] = ""
	}
	stub.out["iptables -L FORWARD -n -v --line-numbers"] = "Chain FORWARD (policy DROP)\nnum pkts bytes target prot opt in out source destination\n"
	stub.calls = nil
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"a and b","source_type":"network","source_network_id":"`+
		a.ID+`","dest_type":"network","dest_network_id":"`+b.ID+`","protocol":"all","action":"accept","priority":100,"enabled":true,"bidirectional":true}`, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"bidirectional":true`) {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	calls := strings.Join(stub.calls, "\n")
	for _, want := range []string{"-s 10.73.0.0/24 -d 10.74.0.0/24 -j ACCEPT", "-s 10.74.0.0/24 -d 10.73.0.0/24 -j ACCEPT"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in\n%s", want, calls)
		}
	}
	var r models.VPNFirewallRule
	json.Unmarshal(rec.Body.Bytes(), &r)
	got := callAs(t, s, "GET", "/api/v1/firewall/vpn/rules", "", true).Body.String()
	if !strings.Contains(got, `"bidirectional":true`) {
		t.Fatalf("list = %s", got)
	}
	rec = callAs(t, s, "PUT", "/api/v1/firewall/vpn/rules/"+r.ID, `{"name":"a to b","source_type":"network","source_network_id":"`+
		a.ID+`","dest_type":"network","dest_network_id":"`+b.ID+`","protocol":"all","action":"accept","priority":100,"enabled":true,"bidirectional":false}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"bidirectional":false`) {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
}

// VLAN plan M3: "who can reach whom" between a device, a network or a group.
func TestAccessCheckEndpoint(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	other := &models.Network{Name: "check-b", CIDR: "10.75.0.0/24", ListenPort: 51875, InterfaceName: "wg75"}
	if err := st.CreateNetwork(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	path := func(ft, fid, tt, tid string) string {
		return "/api/v1/firewall/access-check?from_type=" + ft + "&from_id=" + fid + "&to_type=" + tt + "&to_id=" + tid
	}
	rec := callAs(t, s, "GET", path("node", seed.node.ID, "network", other.ID), "", true)
	if rec.Code != 200 {
		t.Fatalf("check = %d %s", rec.Code, rec.Body)
	}
	var res struct {
		From    struct{ Name string } `json:"from"`
		Forward struct {
			Verdict   string `json:"verdict"`
			ReasonKey string `json:"reason_key"`
		} `json:"forward"`
		Reverse struct{ Verdict string } `json:"reverse"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.From.Name != seed.node.Name || res.Forward.Verdict != "deny" || res.Forward.ReasonKey != "isolated" || res.Reverse.Verdict != "deny" {
		t.Fatalf("isolated by default: %s", rec.Body)
	}
	for _, c := range []struct {
		path string
		code int
	}{
		{path("custom", seed.node.ID, "network", other.ID), 400},
		{path("node", "not-a-uuid", "network", other.ID), 400},
		{path("node", seed.node.ID, "group", "00000000-0000-0000-0000-000000000000"), 404},
	} {
		if rec := callAs(t, s, "GET", c.path, "", true); rec.Code != c.code {
			t.Errorf("%s = %d %s, want %d", c.path, rec.Code, rec.Body, c.code)
		}
	}
}
