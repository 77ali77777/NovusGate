package rest

import (
	"context"
	"strings"
	"testing"
)

// P8: a node with full tunnel (egress) gets a config that sends all IPv4
// traffic through the hub and resolves names over the tunnel.
func TestFullTunnelConfig(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	ctx := context.Background()
	path := "/api/v1/nodes/" + seed.node.ID + "/config"

	before := callAs(t, s, "GET", path, "", true)
	if before.Code != 200 || strings.Contains(before.Body.String(), "0.0.0.0/0") || strings.Contains(before.Body.String(), "DNS =") {
		t.Fatalf("split tunnel config = %d\n%s", before.Code, before.Body)
	}

	if err := st.SetNodeEgress(ctx, seed.node.ID, true); err != nil {
		t.Fatal(err)
	}
	full := callAs(t, s, "GET", path, "", true)
	body := full.Body.String()
	if full.Code != 200 || !strings.Contains(body, "AllowedIPs = 0.0.0.0/0\n") || !strings.Contains(body, "DNS = 1.1.1.1\n") {
		t.Fatalf("full tunnel config = %d\n%s", full.Code, body)
	}
	if strings.Index(body, "DNS = ") > strings.Index(body, "[Peer]") {
		t.Fatal("DNS belongs to the [Interface] section")
	}

	if err := st.SetNodeEgress(ctx, seed.node.ID, false); err != nil {
		t.Fatal(err)
	}
	if after := callAs(t, s, "GET", path, "", true); after.Body.String() != before.Body.String() {
		t.Fatalf("turning full tunnel off must restore the split config:\n%s", after.Body)
	}
}

// P10a: a network may name its own DNS servers for clients (IPv4 only: full
// tunnel routes 0.0.0.0/0, so an IPv6 server would be asked outside it). They go into
// split and full tunnel configs alike; without them full tunnel keeps
// fullTunnelDNS and split tunnel has no DNS line.
func TestNetworkClientDNS(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	path := "/api/v1/nodes/" + seed.node.ID + "/config"
	dnsPath := "/api/v1/networks/" + seed.node.NetworkID + "/dns"

	for _, bad := range []string{`{"client_dns":"not-an-ip"}`, `{"client_dns":"1.1.1.1, 8.8.8.8, 9.9.9.9, 1.0.0.1"}`, `{"client_dns":"1.1.1.1;reboot"}`, `{"client_dns":"2606:4700::1111"}`} {
		if rec := callAs(t, s, "PUT", dnsPath, bad, true); rec.Code != 400 {
			t.Errorf("%s = %d %s, want 400", bad, rec.Code, rec.Body)
		}
	}
	rec := callAs(t, s, "PUT", dnsPath, `{"client_dns":" 10.66.0.53 , 9.9.9.9 "}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"client_dns":"10.66.0.53, 9.9.9.9"`) {
		t.Fatalf("set dns = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", dnsPath, rec)
	if body := callAs(t, s, "GET", path, "", true).Body.String(); !strings.Contains(body, "DNS = 10.66.0.53, 9.9.9.9\n") || strings.Contains(body, "0.0.0.0/0") {
		t.Fatalf("split config with network DNS:\n%s", body)
	}
	if err := st.SetNodeEgress(context.Background(), seed.node.ID, true); err != nil {
		t.Fatal(err)
	}
	if body := callAs(t, s, "GET", path, "", true).Body.String(); !strings.Contains(body, "DNS = 10.66.0.53, 9.9.9.9\n") {
		t.Fatalf("full config with network DNS:\n%s", body)
	}
	if rec := callAs(t, s, "PUT", dnsPath, `{"client_dns":""}`, true); rec.Code != 200 {
		t.Fatalf("clear dns = %d", rec.Code)
	}
	if body := callAs(t, s, "GET", path, "", true).Body.String(); !strings.Contains(body, "DNS = 1.1.1.1\n") {
		t.Fatalf("full config after clearing:\n%s", body)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/networks/00000000-0000-0000-0000-000000000000/dns", `{"client_dns":""}`, true); rec.Code != 404 {
		t.Fatalf("unknown network = %d", rec.Code)
	}
}
