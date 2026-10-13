package firewall

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type fakeSource struct {
	networks []*models.Network
	rules    []*models.VPNFirewallRule
	nodes    map[string]*models.Node
	getCalls int
}

func (f *fakeSource) ListNetworks(context.Context) ([]*models.Network, error) { return f.networks, nil }
func (f *fakeSource) ListVPNFirewallRules(context.Context) ([]*models.VPNFirewallRule, error) {
	return f.rules, nil
}
func (f *fakeSource) GetNode(_ context.Context, id string) (*models.Node, error) {
	f.getCalls++
	return f.nodes[id], nil
}

func TestBuildRulesetCompiles(t *testing.T) {
	src := &fakeSource{
		networks: []*models.Network{
			{ID: "n0", Name: "Admin", CIDR: "10.99.0.0/24", InterfaceName: "wg0", ListenPort: 51820},
			{ID: "n1", Name: "Office", CIDR: "10.20.0.0/24", InterfaceName: "wg1", ListenPort: 51821},
		},
		rules: []*models.VPNFirewallRule{
			{ID: "r1", Name: "office-to-printer", SourceType: "network", SourceNetworkID: strPtr("n1"),
				DestType: "node", DestNodeID: strPtr("p1"), Protocol: "tcp", Port: "9100", Action: "accept", Enabled: true},
			{ID: "r2", Name: "same-node-again", SourceType: "node", SourceNodeID: strPtr("p1"),
				DestType: "any", Protocol: "all", Action: "drop", Enabled: true},
		},
		nodes: map[string]*models.Node{"p1": {ID: "p1", VirtualIP: net.ParseIP("10.99.0.50")}},
	}

	rs, warnings, err := BuildRuleset(context.Background(), src, []uint16{22}, "eth0")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("BuildRuleset: %v, warnings %v", err, warnings)
	}
	if src.getCalls != 1 {
		t.Fatalf("each referenced node must be loaded once, got %d calls", src.getCalls)
	}
	script, err := nft.Compile(rs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `ip saddr 10.20.0.0/24 ip daddr 10.99.0.50/32 tcp dport { 9100 } counter accept comment "rule:r1"`) {
		t.Fatalf("missing converted rule:\n%s", script)
	}
}

type fakeHost struct{ out map[string]string }

func (f fakeHost) Run(_ string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if out, ok := f.out[cmd]; ok {
		return out, nil
	}
	return "not found", errors.New("exit status 127")
}

func TestDetectHost(t *testing.T) {
	ports, egress, err := DetectHost(fakeHost{out: map[string]string{
		"sshd -T":              "port 2222\nport 22\npermitrootlogin yes\n",
		"ip route get 8.8.8.8": "8.8.8.8 via 192.0.2.1 dev ens3 src 192.0.2.10 uid 0\n",
	}})
	if err != nil || len(ports) != 2 || egress != "ens3" {
		t.Fatalf("DetectHost = %v, %q, %v", ports, egress, err)
	}
	if _, _, err := DetectHost(fakeHost{out: map[string]string{}}); err == nil {
		t.Fatal("missing sshd must be an error, never a guessed port")
	}
	// sshd -T fails without /run/sshd; the live listeners must still be found.
	ports, _, err = DetectHost(fakeHost{out: map[string]string{
		"ss -Htlnp":            `LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=7,fd=3))`,
		"ip route get 8.8.8.8": "8.8.8.8 dev eth0 src 192.0.2.10 uid 0",
	}})
	if err != nil || len(ports) != 2 || ports[0] != 22 || ports[1] != 2200 {
		t.Fatalf("ss fallback: DetectHost = %v, %v; want [22 2200]", ports, err)
	}
}
