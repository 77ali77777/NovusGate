package rest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// iptables mode: VPN rules live in chain NOVUSGATE-VPN, jumped to from the
// top of FORWARD, so they come before the wg ACCEPTs WireGuard's PostUp adds
// (appended rules never matched). Replies of allowed connections return
// first; rules follow priority order; creating a rule re-syncs them all.
func TestVPNRulesUseTheirOwnChainInIptablesMode(t *testing.T) {
	s, st, stub := newContractServer(t)
	ctx := context.Background()
	a := &models.Network{Name: "chain-a", CIDR: "10.61.0.0/24", ListenPort: 51861, InterfaceName: "wg61"}
	b := &models.Network{Name: "chain-b", CIDR: "10.62.0.0/24", ListenPort: 51862, InterfaceName: "wg62"}
	for _, n := range []*models.Network{a, b} {
		if err := st.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range []string{"iptables -F NOVUSGATE-VPN", "iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"} {
		stub.out[cmd] = ""
	}
	stub.out["iptables -L FORWARD -n -v --line-numbers"] = "Chain FORWARD (policy DROP)\nnum pkts bytes target prot opt in out source destination\n" +
		"1 0 0 ACCEPT all -- * * 10.0.0.0/8 0.0.0.0/0 /* novusgate-vpn-old */\n"

	create := func(body string) string {
		rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", body, true)
		if rec.Code != 201 {
			t.Fatalf("create = %d %s", rec.Code, rec.Body)
		}
		var r models.VPNFirewallRule
		json.Unmarshal(rec.Body.Bytes(), &r)
		return r.ID
	}
	create(`{"name":"a to b","source_type":"network","source_network_id":"` + a.ID + `","dest_type":"network","dest_network_id":"` + b.ID + `","protocol":"all","action":"accept","priority":200,"enabled":true}`)
	stub.calls = nil
	sshID := create(`{"name":"no ssh","source_type":"network","source_network_id":"` + a.ID + `","dest_type":"network","dest_network_id":"` + b.ID + `","protocol":"tcp","port":"22","action":"drop","priority":100,"enabled":true}`)

	calls := strings.Join(stub.calls, "\n")
	for _, want := range []string{
		"iptables -D FORWARD 1", // the legacy rule appended to FORWARD is removed
		"iptables -N NOVUSGATE-VPN",
		"iptables -F NOVUSGATE-VPN",
		"iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"iptables -A NOVUSGATE-VPN -s 10.61.0.0/24 -d 10.62.0.0/24 -p tcp --dport 22 -j DROP -m comment --comment novusgate-vpn-" + sshID,
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "iptables -A FORWARD") {
		t.Errorf("VPN rules must not be appended to FORWARD:\n%s", calls)
	}
	// priority 100 (drop ssh) before priority 200 (accept all)
	drop := strings.Index(calls, "--dport 22 -j DROP")
	accept := strings.Index(calls, "-s 10.61.0.0/24 -d 10.62.0.0/24 -j ACCEPT")
	if drop < 0 || accept < 0 || drop > accept {
		t.Errorf("rules out of priority order (drop at %d, accept at %d):\n%s", drop, accept, calls)
	}
}

// iptables writes port ranges as a:b; "8000-9000" (accepted by the form
// and by nftables) was passed through, iptables refused it and the rule was
// saved but never enforced.
func TestVPNRulePortRangeInIptablesMode(t *testing.T) {
	s, st, stub := newContractServer(t)
	ctx := context.Background()
	a := &models.Network{Name: "range-a", CIDR: "10.63.0.0/24", ListenPort: 51863, InterfaceName: "wg63"}
	b := &models.Network{Name: "range-b", CIDR: "10.64.0.0/24", ListenPort: 51864, InterfaceName: "wg64"}
	for _, n := range []*models.Network{a, b} {
		if err := st.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range []string{"iptables -F NOVUSGATE-VPN", "iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"} {
		stub.out[cmd] = ""
	}
	stub.out["iptables -L FORWARD -n -v --line-numbers"] = "Chain FORWARD (policy DROP)\n"
	stub.calls = nil
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"range","source_type":"network","source_network_id":"`+a.ID+
		`","dest_type":"network","dest_network_id":"`+b.ID+`","protocol":"tcp","port":"8000-9000, 22","action":"drop","priority":100,"enabled":true}`, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"port":"8000-9000, 22"`) {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	calls := strings.Join(stub.calls, "\n")
	if !strings.Contains(calls, "-m multiport --dports 8000:9000,22 -j DROP") {
		t.Fatalf("iptables ports not in a:b form:\n%s", calls)
	}
}
