package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
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
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 10.0.0.0/8\n") {
		t.Fatalf("no rule yet, still every network (the pool holds them):\n%s", conf)
	}
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"to lan","source_type":"network","source_network_id":"`+
		seed.network.ID+`","dest_type":"custom","dest_ip":"192.168.50.0/24","protocol":"all","action":"accept","priority":100,"enabled":true}`, true)
	if rec.Code != 201 {
		t.Fatalf("rule = %d %s", rec.Code, rec.Body)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 10.0.0.0/8, 192.168.50.0/24\n") {
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
	// Since the pool (P1) a new network inside it changes nothing; one
	// outside it (made before the pool existed) still does.
	n := &models.Network{Name: "contract-routes-new", CIDR: "192.168.69.0/24", ListenPort: 51869, InterfaceName: "wg69"}
	if err := st.CreateNetwork(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if !outdated() {
		t.Fatal("a new network outside the pool makes the config outdated")
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
		"iptables -A NOVUSGATE-VPN -i wg+ -o wg+ -j DROP -m comment --comment novusgate-vpn-isolation",
		"iptables -A NOVUSGATE-VPN -i wg+ -d 10.0.0.0/8 -j DROP -m comment --comment novusgate-vpn-isolation"} {
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
	// The pool (server-side routing): devices route all of it into the
	// tunnel, so hub-side 10.x hosts that no rule names are dropped too.
	if pool := strings.Index(calls, "iptables -A NOVUSGATE-VPN -i wg+ -d 10.0.0.0/8 -j DROP"); pool < accept {
		t.Fatalf("rules, then the pool DROP:\n%s", calls)
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
		"iptables -A NOVUSGATE-VPN -i wg+ -o wg+ -j DROP -m comment --comment novusgate-vpn-isolation",
		"iptables -A NOVUSGATE-VPN -i wg+ -d 10.0.0.0/8 -j DROP -m comment --comment novusgate-vpn-isolation"} {
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

// VLAN plan M4: a device gets a new key and config; the old config stops
// working at once (its peer is removed), the new one is a fresh download.
func TestRotateNodeKey(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	old := seed.node.PublicKey
	own := seed.node.VirtualIP.String() + "/32"
	f := &fakePC{peers: map[string]wireguard.PeerStatus{old: {AllowedIPs: own}}}
	orig := nodePeerControl
	t.Cleanup(func() { nodePeerControl = orig })
	nodePeerControl = func(*Server, string) peerControl { return f }
	configOf(t, s, seed.node.ID)

	rec := callAs(t, s, "POST", "/api/v1/nodes/"+seed.node.ID+"/rotate-key", "", true)
	if rec.Code != 200 {
		t.Fatalf("rotate = %d %s", rec.Code, rec.Body)
	}
	var n models.Node
	if err := json.Unmarshal(rec.Body.Bytes(), &n); err != nil {
		t.Fatal(err)
	}
	if n.PublicKey == "" || n.PublicKey == old || !n.ConfigOutdated {
		t.Fatalf("new key, config to download again: %s", rec.Body)
	}
	if want := []string{"remove " + old, "add " + n.PublicKey + " " + own}; !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	conf := configOf(t, s, seed.node.ID)
	var priv string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			priv = strings.TrimPrefix(line, "PrivateKey = ")
		}
	}
	if pub, err := wireguard.PublicKey(priv); err != nil || pub != n.PublicKey {
		t.Fatalf("the config carries the new key: %v %q", err, pub)
	}
	if rec := callAs(t, s, "POST", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/rotate-key", "", true); rec.Code != 404 {
		t.Fatalf("unknown device = %d", rec.Code)
	}
}

type failRemove struct{ *fakePC }

func (failRemove) RemovePeer(string) error { return errors.New("wg: device busy") }

// If the old peer cannot be removed, nothing changes: a "new" key beside a
// still-working old config would be worse than no rotation.
func TestRotateNodeKeyKeepsTheKeyWhenThePeerStays(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	orig := nodePeerControl
	t.Cleanup(func() { nodePeerControl = orig })
	nodePeerControl = func(*Server, string) peerControl {
		return failRemove{&fakePC{peers: map[string]wireguard.PeerStatus{}}}
	}
	if rec := callAs(t, s, "POST", "/api/v1/nodes/"+seed.node.ID+"/rotate-key", "", true); rec.Code != 500 {
		t.Fatalf("rotate = %d %s", rec.Code, rec.Body)
	}
	if n, _ := st.GetNode(context.Background(), seed.node.ID); n.PublicKey != seed.node.PublicKey {
		t.Fatalf("key changed: %s", n.PublicKey)
	}
}

// Review 2026-10-19: an outside range a rule names is routed only by the
// devices on the rule's other side, not by every device of every network.
func TestCustomRangeRoutedOnlyByTheOtherSide(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	other := &models.Node{NetworkID: seed.empty.ID, Name: "elsewhere", VirtualIP: net.ParseIP("10.68.0.3"),
		PublicKey: strings.Repeat("O", 43) + "=", Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := st.CreateNode(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodePrivateKey(context.Background(), other.ID, strings.Repeat("Q", 43)+"="); err != nil {
		t.Fatal(err)
	}
	rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"lan to net","source_type":"custom","source_ip":"192.168.50.0/24",`+
		`"dest_type":"network","dest_network_id":"`+seed.network.ID+`","protocol":"all","action":"accept","priority":100,"enabled":true}`, true)
	if rec.Code != 201 {
		t.Fatalf("rule = %d %s", rec.Code, rec.Body)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "192.168.50.0/24") {
		t.Fatalf("the rule's other side routes the range (replies):\n%s", conf)
	}
	if conf := configOf(t, s, other.ID); strings.Contains(conf, "192.168.50.0/24") {
		t.Fatalf("a device the rule does not cover keeps its own route to the range:\n%s", conf)
	}
}

// A custom 0.0.0.0/0 would put a full tunnel in configs; "any" says it.
func TestCustomRangeMayNotBeEverything(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	for _, ip := range []string{"0.0.0.0/0", "0.0.0.0"} {
		rec := callAs(t, s, "POST", "/api/v1/firewall/vpn/rules", `{"name":"all","source_type":"network","source_network_id":"`+
			seed.network.ID+`","dest_type":"custom","dest_ip":"`+ip+`","protocol":"all","action":"accept","priority":100,"enabled":true}`, true)
		if ip == "0.0.0.0/0" && rec.Code != 400 {
			t.Errorf("%s = %d %s", ip, rec.Code, rec.Body)
		}
	}
}

// iptables mode: deleting a device rebuilds NOVUSGATE-VPN, so an ACCEPT for
// its address does not pass to the next device that gets it.
func TestIptablesRebuildsAfterNodeDelete(t *testing.T) {
	s, st, stub := newContractServer(t)
	seed := seedContract(t, st)
	for _, cmd := range []string{"iptables -F NOVUSGATE-VPN", "iptables -I FORWARD 1 -i wg+ -j NOVUSGATE-VPN",
		"iptables -A NOVUSGATE-VPN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"iptables -A NOVUSGATE-VPN -i wg66 -o wg66 -j RETURN", "iptables -A NOVUSGATE-VPN -i wg68 -o wg68 -j RETURN",
		"iptables -A NOVUSGATE-VPN -i wg+ -o wg+ -j DROP -m comment --comment novusgate-vpn-isolation",
		"iptables -A NOVUSGATE-VPN -i wg+ -d 10.0.0.0/8 -j DROP -m comment --comment novusgate-vpn-isolation"} {
		stub.out[cmd] = ""
	}
	stub.out["iptables -L FORWARD -n -v --line-numbers"] = "Chain FORWARD (policy DROP)\nnum pkts bytes target prot opt in out source destination\n"
	stub.calls = nil
	if rec := callAs(t, s, "DELETE", "/api/v1/nodes/"+seed.node.ID, "", true); rec.Code != 200 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if calls := strings.Join(stub.calls, "\n"); !strings.Contains(calls, "iptables -F NOVUSGATE-VPN") ||
		!strings.Contains(calls, "--comment novusgate-vpn-isolation") {
		t.Fatalf("chain not rebuilt:\n%s", calls)
	}
}

// Review 2026-10-19: rotating the key of the device the request comes
// through would cut the caller off before the new config is downloaded.
func TestRotateNodeKeyRefusesTheCallersOwnDevice(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	req := httptest.NewRequest("POST", "/api/v1/nodes/"+seed.node.ID+"/rotate-key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = seed.node.VirtualIP.String() + ":5555"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "rotate_own_device") {
		t.Fatalf("rotate own device = %d %s", rec.Code, rec.Body)
	}
}

type takenAddress struct{ *fakePC }

func (takenAddress) GetPeers() (map[string]wireguard.PeerStatus, error) {
	return map[string]wireguard.PeerStatus{"SOMEONE": {AllowedIPs: "10.66.0.3/32"}}, nil
}

// Review 2026-10-19: a new peer that could not be added is an error, not a
// success: the device would have no working config at all.
func TestRotateNodeKeyReportsTheNewPeerFailing(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	orig := nodePeerControl
	t.Cleanup(func() { nodePeerControl = orig })
	nodePeerControl = func(*Server, string) peerControl {
		return takenAddress{&fakePC{peers: map[string]wireguard.PeerStatus{}}}
	}
	rec := callAs(t, s, "POST", "/api/v1/nodes/"+seed.node.ID+"/rotate-key", "", true)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "rotate_peer_not_added") {
		t.Fatalf("rotate = %d %s", rec.Code, rec.Body)
	}
}
