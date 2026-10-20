package rest

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/dnsfwd"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Server-side routing P3: a config names the hub as its DNS server; the
// hub forwards to the network's DNS servers, so changing them changes no
// config. Without a running forwarder the config names them directly.

// testDNSAddrs maps each hub address to a free loopback port (a test
// cannot bind 10.x.y.1:53).
func testDNSAddrs(t *testing.T) {
	t.Helper()
	addrs := map[string]string{}
	orig := dnsListenAddr
	t.Cleanup(func() { dnsListenAddr = orig })
	dnsListenAddr = func(hub string) string {
		if a, ok := addrs[hub]; ok {
			return a
		}
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[hub] = pc.LocalAddr().String()
		pc.Close()
		return addrs[hub]
	}
}

func TestConfigDNSIsTheHub(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st) // contract-net 10.66.0.0/24: hub 10.66.0.1
	ctx := context.Background()
	if _, err := st.SetNetworkClientDNS(ctx, seed.network.ID, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "DNS = 9.9.9.9\n") {
		t.Fatalf("no forwarder: the network's DNS servers directly:\n%s", conf)
	}

	testDNSAddrs(t)
	s.EnableDNS(dnsfwd.New(time.Second))
	t.Cleanup(func() { s.dns.Close() })
	s.SyncDNS(ctx)
	conf := configOf(t, s, seed.node.ID)
	if !strings.Contains(conf, "DNS = 10.66.0.1\n") {
		t.Fatalf("the hub answers DNS:\n%s", conf)
	}
	// New DNS servers: the forwarder changes, the config does not.
	if _, err := st.SetNetworkClientDNS(ctx, seed.network.ID, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	s.SyncDNS(ctx)
	if body := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID, "", true).Body.String(); !strings.Contains(body, `"config_outdated":false`) {
		t.Fatalf("new DNS servers need no new config: %s", body)
	}
	// Still the hub after the change.
	if conf := configOf(t, s, seed.node.ID); !strings.Contains(conf, "DNS = 10.66.0.1\n") {
		t.Fatalf("still the hub:\n%s", conf)
	}
	if _, err := st.SetNetworkClientDNS(ctx, seed.network.ID, ""); err != nil {
		t.Fatal(err)
	}
	if conf := configOf(t, s, seed.node.ID); strings.Contains(conf, "DNS =") {
		t.Fatalf("no DNS servers, split tunnel: no DNS line:\n%s", conf)
	}
}

// Review P3: a listener answers only its network's range, and a hub
// address is never an upstream (the forwarder would forward to itself).
func TestDNSTargets(t *testing.T) {
	nets := []*models.Network{
		{Name: "a", CIDR: "10.10.0.0/24", InterfaceName: "wg1", ClientDNS: "10.20.0.1, 10.10.0.1, 10.10.0.53"},
		{Name: "b", CIDR: "10.20.0.0/24", InterfaceName: "wg2", ClientDNS: "10.10.0.1"},
		{Name: "down", CIDR: "10.30.0.0/24"},
	}
	got := dnsTargets(nets)
	a := got[dnsListenAddr("10.10.0.1")]
	if a.Allow != netip.MustParsePrefix("10.10.0.0/24") || strings.Join(a.Upstreams, ",") != "10.10.0.53:53" {
		t.Fatalf("a = %+v", a)
	}
	if b := got[dnsListenAddr("10.20.0.1")]; strings.Join(b.Upstreams, ",") != "1.1.1.1:53" {
		t.Fatalf("only hub addresses: the default; b = %+v", b)
	}
	if len(got) != 2 {
		t.Fatalf("a network without interface has no listener: %v", got)
	}
}

func TestClientDNSMayNotBeAHubAddress(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	rec := callAs(t, s, "PUT", "/api/v1/networks/"+seed.network.ID+"/dns", `{"client_dns":"10.68.0.1"}`, true)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "dns_is_hub") {
		t.Fatalf("another network's hub = %d %s", rec.Code, rec.Body)
	}
}
