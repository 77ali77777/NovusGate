package rest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestPolicyMatrixEndpoint(t *testing.T) {
	s, st, _ := newContractServer(t)
	ctx := context.Background()
	a := &models.Network{Name: "matrix-a", CIDR: "10.71.0.0/24", ListenPort: 51871, InterfaceName: "wg71"}
	b := &models.Network{Name: "matrix-b", CIDR: "10.72.0.0/24", ListenPort: 51872, InterfaceName: "wg72"}
	for _, n := range []*models.Network{a, b} {
		if err := st.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateVPNFirewallRule(ctx, &models.VPNFirewallRule{Name: "a to b drop", SourceType: "network", SourceNetworkID: &a.ID,
		DestType: "network", DestNetworkID: &b.ID, Protocol: "all", Action: "drop", Priority: 100, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := callAs(t, s, "GET", "/api/v1/firewall/policy-matrix", "", true)
	if rec.Code != 200 {
		t.Fatalf("matrix = %d %s", rec.Code, rec.Body)
	}
	var m firewall.Matrix
	json.Unmarshal(rec.Body.Bytes(), &m)
	// No nft engine here: iptables mode, which keeps networks apart by
	// default too (NOVUSGATE-VPN ends with a DROP between networks).
	if m.NftEnforcing || m.Cells[a.ID][b.ID].Verdict != "deny" || m.Cells[b.ID][a.ID].Verdict != "deny" ||
		m.Cells[b.ID][a.ID].ReasonKey != "isolated" ||
		len(m.Cells[a.ID][b.ID].Rules) != 1 {
		t.Fatalf("matrix = %s", rec.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/firewall/policy-matrix", rec)

	s2, _ := newEngineServer(t, firewall.ModeNft)
	rec = callAs(t, s2, "GET", "/api/v1/firewall/policy-matrix", "", true)
	json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != 200 || !m.NftEnforcing {
		t.Fatalf("nft matrix = %d %s", rec.Code, rec.Body)
	}
}
