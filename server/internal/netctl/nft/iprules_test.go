package nft

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func ipRulesRuleset() Ruleset {
	rs := fullRuleset()
	rs.IPRules = []IPRule{
		{ID: "no-web", Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: "block", Proto: TCP,
			Ports: []PortRange{{80, 80}, {443, 443}}},
		{ID: "office", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Action: "allow"},
		{ID: "monitor", Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Action: "allow", Proto: UDP,
			Ports: []PortRange{{161, 162}}},
	}
	return rs
}

func TestIPRulesRendering(t *testing.T) {
	got, err := Compile(ipRulesRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	block := `ip saddr 203.0.113.7 tcp dport { 80, 443 } counter drop comment "ip:no-web"`
	allowAll := `ip saddr 198.51.100.0/24 accept comment "ip:office"`
	allowV6 := `ip6 saddr 2001:db8:1::/48 udp dport { 161-162 } accept comment "ip:monitor"`
	for _, s := range []string{block, allowAll, allowV6} {
		if !strings.Contains(got, s) {
			t.Fatalf("missing %q\n%s", s, got)
		}
	}
	est := strings.Index(got, "ct state established,related accept")
	if strings.Index(got, block) > est {
		t.Fatal("port-scoped blocks must come before established, so they cut live connections")
	}
	if strings.Index(got, allowAll) < strings.Index(got, `comment "svc:https"`) {
		t.Fatal("allows come after the services")
	}
}

// An allow rule (spec §6b.4) must not open the VPN-only admin and API ports
// to its source: the guard drop sits after the VPN accepts and before the allows.
func TestAllowsCannotOpenAdminPorts(t *testing.T) {
	got, err := Compile(ipRulesRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	guard := `tcp dport { 3007, 5432, 8080, 8443 } counter drop comment "admin ports: VPN only"`
	g := strings.Index(got, guard)
	if g < 0 {
		t.Fatalf("missing %q\n%s", guard, got)
	}
	if g < strings.Index(got, `iifname "wg0" tcp dport { 3007, 5432 } accept`) ||
		g < strings.Index(got, `tcp dport { 8080, 8443 } accept`) {
		t.Fatal("the guard must come after the VPN accepts of the admin and API ports")
	}
	if g > strings.Index(got, `comment "ip:office"`) {
		t.Fatal("the guard must come before the allow rules")
	}
}

func TestIPRulesValidation(t *testing.T) {
	cases := map[string]IPRule{
		"block without ports": {ID: "x", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "block"},
		"ports without proto": {ID: "x", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "allow", Ports: []PortRange{{1, 2}}},
		"unknown action":      {ID: "x", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "deny", Proto: TCP, Ports: []PortRange{{1, 2}}},
		"injection in id":     {ID: `x" accept`, Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "allow"},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			rs := fullRuleset()
			rs.IPRules = []IPRule{r}
			if _, err := Compile(rs, testNow); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestGuardRefusesPortBlockOfOperator(t *testing.T) {
	rs := ipRulesRuleset()
	p := Protection{SSHPorts: []uint16{22}, Addrs: []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.7")}}
	if err := CheckProtection(rs, p, testNow); err == nil {
		t.Fatal("blocking the operator's address on any port must be refused (IPv4-mapped included)")
	}
}

func TestIPRulesLoadInKernel(t *testing.T) {
	if os.Getenv("NFT_CHECK") != "1" {
		t.Skip("set NFT_CHECK=1 to validate against the kernel")
	}
	script, err := Compile(ipRulesRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the ruleset: %v\n%s", err, out)
	}
}
