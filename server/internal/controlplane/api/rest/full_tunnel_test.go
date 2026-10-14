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
