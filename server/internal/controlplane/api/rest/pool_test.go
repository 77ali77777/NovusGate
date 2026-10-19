package rest

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// Config once, server decides (plan 2026-10-19 "server-side routing", P1):
// every config routes one address pool; networks are made inside it, so a
// new network never changes a device's config.

func TestNextNetworkCIDR(t *testing.T) {
	pfx := netip.MustParsePrefix
	used := []netip.Prefix{pfx("10.10.0.0/24"), pfx("10.99.0.0/24")}
	if got, ok := nextNetworkCIDR(pfx("10.0.0.0/8"), used); !ok || got != pfx("10.11.0.0/24") {
		t.Fatalf("10/8: %v %v, want 10.11.0.0/24 (one /16 per network, from 10.10)", got, ok)
	}
	if got, ok := nextNetworkCIDR(pfx("10.20.0.0/16"), []netip.Prefix{pfx("10.20.0.0/24")}); !ok || got != pfx("10.20.1.0/24") {
		t.Fatalf("a /16 pool goes /24 by /24: %v %v", got, ok)
	}
	// A wide network inside the pool is skipped as a whole.
	if got, _ := nextNetworkCIDR(pfx("10.0.0.0/8"), []netip.Prefix{pfx("10.10.0.0/16")}); got != pfx("10.11.0.0/24") {
		t.Fatalf("overlap: %v", got)
	}
	if _, ok := nextNetworkCIDR(pfx("10.20.0.0/24"), []netip.Prefix{pfx("10.20.0.0/24")}); ok {
		t.Fatal("a full pool has no next network")
	}
}

func TestValidPool(t *testing.T) {
	for _, ok := range []string{"10.0.0.0/8", "10.96.0.0/12", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "10.20.0.0/16"} {
		if _, err := validPool(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "x", "8.8.0.0/16", "10.0.0.0/7", "10.20.0.0/17", "10.0.0.1/8", "fd00::/8"} {
		if _, err := validPool(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestConfigRoutesThePool(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st) // 10.66.0.0/24 and 10.68.0.0/24: inside 10.0.0.0/8
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 10.0.0.0/8\n") {
		t.Fatalf("the pool, not each network:\n%s", conf)
	}
	// A network made before the pool, outside it, is still routed by name.
	old := &models.Network{Name: "legacy", CIDR: "192.168.77.0/24", ListenPort: 51877, InterfaceName: "wg77"}
	if err := st.CreateNetwork(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "AllowedIPs = 10.0.0.0/8, 192.168.77.0/24\n") {
		t.Fatalf("outside network routed too:\n%s", conf)
	}
}

func TestNewNetworkInsideThePoolKeepsConfigs(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	configOf(t, s, seed.node.ID)
	n := &models.Network{Name: "later", CIDR: "10.69.0.0/24", ListenPort: 51869, InterfaceName: "wg69"}
	if err := st.CreateNetwork(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if body := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID, "", true).Body.String(); !strings.Contains(body, `"config_outdated":false`) {
		t.Fatalf("a new network inside the pool needs no new config: %s", body)
	}
}

func TestCreateNetworkPicksItsCIDR(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"auto"}`, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"cidr":"10.10.0.0/24"`) {
		t.Fatalf("auto = %d %s", rec.Code, rec.Body)
	}
	rec = callAs(t, s, "POST", "/api/v1/networks", `{"name":"outside","cidr":"192.168.5.0/24"}`, true)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "cidr_outside_pool") {
		t.Fatalf("outside the pool = %d %s", rec.Code, rec.Body)
	}
}

func TestVPNSettingsAPI(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	// The settings row outlives the test database's other rows.
	t.Cleanup(func() { st.SetVPNPool(context.Background(), "10.0.0.0/8") })
	var got struct {
		Pool     string `json:"pool"`
		NextCIDR string `json:"next_cidr"`
	}
	rec := callAs(t, s, "GET", "/api/v1/settings/vpn", "", true)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Pool != "10.0.0.0/8" || got.NextCIDR != "10.10.0.0/24" {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/settings/vpn", `{"pool":"10.64.0.0/10"}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"pool":"10.64.0.0/10"`) {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{`{"pool":"8.8.0.0/16"}`, `{"pool":"10.0.0.0/7"}`, `{`} {
		if rec := callAs(t, s, "PUT", "/api/v1/settings/vpn", bad, true); rec.Code != 400 {
			t.Errorf("%s = %d %s", bad, rec.Code, rec.Body)
		}
	}
}

// P2: configs name the hub by a domain, so a new server IP changes only a
// DNS record, not any config.
func TestEndpointHostInConfigs(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	t.Cleanup(func() { st.SetVPNEndpointHost(context.Background(), "") })
	configOf(t, s, seed.node.ID)
	rec := callAs(t, s, "PUT", "/api/v1/settings/vpn", `{"endpoint_host":"vpn.example.com"}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"endpoint_host":"vpn.example.com"`) || !strings.Contains(rec.Body.String(), `"pool":"10.0.0.0/8"`) {
		t.Fatalf("put host = %d %s", rec.Code, rec.Body)
	}
	if body := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID, "", true).Body.String(); !strings.Contains(body, `"config_outdated":true`) {
		t.Fatalf("a new endpoint makes the config outdated once: %s", body)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "Endpoint = vpn.example.com:51866\n") {
		t.Fatalf("endpoint by name and the network's port:\n%s", conf)
	}
	if body := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID, "", true).Body.String(); !strings.Contains(body, `"config_outdated":false`) {
		t.Fatalf("downloaded: up to date: %s", body)
	}
	for _, bad := range []string{`{"endpoint_host":"http://vpn.example.com"}`, `{"endpoint_host":"vpn.example.com:51820"}`, `{"endpoint_host":"a..b"}`, `{}`} {
		if rec := callAs(t, s, "PUT", "/api/v1/settings/vpn", bad, true); rec.Code != 400 {
			t.Errorf("%s = %d %s", bad, rec.Code, rec.Body)
		}
	}
	if rec := callAs(t, s, "PUT", "/api/v1/settings/vpn", `{"endpoint_host":"198.51.100.7"}`, true); rec.Code != 200 {
		t.Fatalf("an IPv4 address = %d %s", rec.Code, rec.Body)
	}
	callAs(t, s, "PUT", "/api/v1/settings/vpn", `{"endpoint_host":""}`, true)
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "Endpoint = 203.0.113.1\n") {
		t.Fatalf("cleared: the network's own endpoint again:\n%s", conf)
	}
}

// Review P1/P2: a hub reached at an address inside the pool would have its
// own handshakes routed into the tunnel; such configs name the networks.
func TestEndpointInsideThePoolKeepsNetworkRoutes(t *testing.T) {
	s, st, _ := newContractServer(t)
	ctx := context.Background()
	key := func(c string) string { return strings.Repeat(c, 43) + "=" }
	n := &models.Network{Name: "private-hub", CIDR: "10.70.0.0/24", ServerPrivateKey: key("s"), ServerPublicKey: key("S"),
		ServerEndpoint: "10.200.0.9:51870", ListenPort: 51870, InterfaceName: "wg70"}
	if err := st.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	node := &models.Node{NetworkID: n.ID, Name: "behind", VirtualIP: net.ParseIP("10.70.0.3"), PublicKey: key("N"),
		Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := st.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodePrivateKey(ctx, node.ID, key("P")); err != nil {
		t.Fatal(err)
	}
	conf := configOf(t, s, node.ID)
	if strings.Contains(conf, "10.0.0.0/8") || !strings.Contains(conf, "AllowedIPs = 10.70.0.0/24") {
		t.Fatalf("endpoint 10.200.0.9 is inside the pool: networks by name:\n%s", conf)
	}
	t.Cleanup(func() { st.SetVPNEndpointHost(ctx, "") })
	for _, bad := range []string{`{"endpoint_host":"10.1.2.3"}`, `{"endpoint_host":"999.1.1.1"}`, `{"endpoint_host":"1.2.3"}`} {
		if rec := callAs(t, s, "PUT", "/api/v1/settings/vpn", bad, true); rec.Code != 400 {
			t.Errorf("%s = %d %s", bad, rec.Code, rec.Body)
		}
	}
}
