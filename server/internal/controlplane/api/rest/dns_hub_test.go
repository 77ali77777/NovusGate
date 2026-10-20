package rest

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/dnsfwd"
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
	// A split-tunnel network without DNS servers still hands out none.
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
