package nft

import (
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func fullRuleset() Ruleset {
	inOneHour := testNow.Add(time.Hour)
	expired := testNow.Add(-time.Minute)
	return Ruleset{
		SSHPorts:        []uint16{2222, 22, 22},
		EgressInterface: "eth0",
		Networks: []VPNNetwork{
			{Interface: "wg1", CIDR: netip.MustParsePrefix("10.20.0.0/24"), ListenPort: 51821},
			{Interface: "wg0", CIDR: netip.MustParsePrefix("10.99.0.0/24"), ListenPort: 51820},
			{Interface: "wg2", CIDR: netip.MustParsePrefix("10.30.0.0/24"), ListenPort: 51950},
		},
		Services: []Service{
			{ID: "https", Proto: TCP, Ports: PortRange{443, 443}},
			{ID: "office-rdp", Proto: TCP, Ports: PortRange{3389, 3389},
				Sources: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}},
			{ID: "vpn-dns", Proto: UDP, Ports: PortRange{53, 53}, Interface: "wg1"},
		},
		Blocked: []BlockedEntry{
			{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			{Prefix: netip.MustParsePrefix("198.51.100.7/32")}, // covered by the /24
			{Prefix: netip.MustParsePrefix("192.0.2.9/32"), Expires: &inOneHour},
			{Prefix: netip.MustParsePrefix("192.0.2.10/32"), Expires: &expired}, // already expired
			{Prefix: netip.MustParsePrefix("2001:db8:bad::/48")},
		},
		Forwards: []PortForward{
			{ID: "home-cam", Proto: TCP, PublicPort: 8081, TargetIP: netip.MustParseAddr("10.20.0.5"), TargetPort: 80},
		},
		VPNRules: []VPNRule{
			{ID: "block-ssh-a-b", Src: netip.MustParsePrefix("10.20.0.0/24"), Dst: netip.MustParsePrefix("10.30.0.0/24"),
				Proto: TCP, Ports: []PortRange{{22, 22}}, Action: "drop"},
			{ID: "a-to-b-web", Src: netip.MustParsePrefix("10.20.0.0/24"), Dst: netip.MustParsePrefix("10.30.0.0/24"),
				Proto: TCP, Ports: []PortRange{{80, 80}, {8000, 8100}}, Action: "accept"},
			{ID: "any-ping", Src: netip.MustParsePrefix("0.0.0.0/0"), Dst: netip.MustParsePrefix("10.30.0.10/32"),
				Proto: ICMP, Action: "accept"},
		},
		Egress: []netip.Addr{netip.MustParseAddr("10.20.0.7"), netip.MustParseAddr("10.20.0.6")},
	}
}

func TestCompileGolden(t *testing.T) {
	got, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	golden := filepath.Join("testdata", "full.nft")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if got != string(want) {
		t.Fatalf("compiled ruleset differs from %s\n--- got ---\n%s", golden, got)
	}
}

func TestCompileKeyBehaviour(t *testing.T) {
	got, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	mustContain := []string{
		"elements = { 22, 2222 }",                                 // SSH ports deduplicated and sorted
		"elements = { 51820-51900, 51950 }",                       // legacy range merged with listen ports
		"elements = { 192.0.2.9 timeout 3600s, 198.51.100.0/24 }", // expired and covered entries dropped
		"type filter hook input priority filter - 10; policy drop;",
		`iifname "wg0" tcp dport { 3007, 5432 } accept`,
		`iifname "wg*" tcp dport { 8080, 8443 } accept`,
		`ip saddr { 203.0.113.0/24 } tcp dport 3389 accept comment "svc:office-rdp"`,
		`ip6 saddr { 2001:db8::/32 } tcp dport 3389 accept comment "svc:office-rdp"`,
		`iifname "wg1" udp dport 53 accept comment "svc:vpn-dns"`,
		`meta l4proto tcp ct original proto-dst 5432 ct status dnat counter drop`,
		`ip saddr 10.20.0.0/24 ip daddr 10.30.0.0/24 tcp dport { 22 } counter drop comment "rule:block-ssh-a-b"`,
		`ip daddr 10.30.0.10/32 meta l4proto icmp counter accept comment "rule:any-ping"`,
		`iifname "wg0" oifname "wg0" accept`,
		`iifname "eth0" tcp dport 8081 dnat ip to 10.20.0.5:80 comment "fwd:home-cam"`,
		`ip daddr 10.20.0.5 oifname "wg1" tcp dport 80 ct status dnat masquerade comment "fwd:home-cam"`,
		"elements = { 10.20.0.6, 10.20.0.7 }",
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q", s)
		}
	}
	// Rule order matters: the drop for port 22 must precede the broader accept.
	if strings.Index(got, "rule:block-ssh-a-b") > strings.Index(got, "rule:a-to-b-web") {
		t.Error("VPN rules must keep their order")
	}
	if strings.Contains(got, "192.0.2.10") || strings.Contains(got, "198.51.100.7") {
		t.Error("expired or covered blocked entries must not be rendered")
	}
}

func TestValidateRejectsUnsafeInput(t *testing.T) {
	cases := map[string]func(*Ruleset){
		"no ssh ports":               func(r *Ruleset) { r.SSHPorts = nil },
		"injection in egress":        func(r *Ruleset) { r.EgressInterface = `eth0" accept` },
		"injection in service id":    func(r *Ruleset) { r.Services[0].ID = `x" accept #` },
		"public admin port":          func(r *Ruleset) { r.Services[0].Ports = PortRange{8000, 8090} },
		"forward on ssh port":        func(r *Ruleset) { r.Forwards[0].PublicPort = 2222 },
		"forward outside vpn":        func(r *Ruleset) { r.Forwards[0].TargetIP = netip.MustParseAddr("192.168.1.10") },
		"ports with icmp":            func(r *Ruleset) { r.VPNRules[2].Ports = []PortRange{{1, 2}} },
		"unknown action":             func(r *Ruleset) { r.VPNRules[0].Action = "allow" },
		"ipv6 egress":                func(r *Ruleset) { r.Egress = []netip.Addr{netip.MustParseAddr("2001:db8::1")} },
		"forward in wireguard range": func(r *Ruleset) { r.Forwards[0].Proto = UDP; r.Forwards[0].PublicPort = 51830 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rs := fullRuleset()
			mutate(&rs)
			if _, err := Compile(rs, testNow); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestAdminPortAllowedOnVPNInterface(t *testing.T) {
	rs := fullRuleset()
	rs.Services = append(rs.Services, Service{ID: "vpn-alt-api", Proto: TCP, Ports: PortRange{8080, 8080}, Interface: "wg1"})
	if _, err := Compile(rs, testNow); err != nil {
		t.Fatalf("a VPN-only service may use an admin port: %v", err)
	}
}

func TestMergeRanges(t *testing.T) {
	got := rangeElems([]PortRange{{51820, 51900}, {51850, 51850}, {51901, 51901}, {60000, 60000}, {10, 20}})
	want := "10-20, 51820-51901, 60000"
	if strings.Join(got, ", ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

// TestCompiledRulesetLoadsInKernel feeds the compiled script to `nft -c`.
// It runs only when NFT_CHECK=1 and needs the nft binary and CAP_NET_ADMIN.
func TestCompiledRulesetLoadsInKernel(t *testing.T) {
	if os.Getenv("NFT_CHECK") != "1" {
		t.Skip("set NFT_CHECK=1 to validate against the kernel")
	}
	script, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the ruleset: %v\n%s", err, out)
	}
}

// Docker DNATs wg0 traffic to the published postgres port, so it goes through
// forward: the admin VPN must keep that access, every other interface loses it.
func TestForwardKeepsAdminAccessToPublishedPostgres(t *testing.T) {
	got, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	accept := `iifname "wg0" meta l4proto tcp ct original proto-dst 5432 ct status dnat accept`
	drop := `meta l4proto tcp ct original proto-dst 5432 ct status dnat counter drop`
	ai, di, ji := strings.Index(got, accept), strings.Index(got, drop), strings.Index(got, "jump vpn_policy")
	if ai < 0 || di < 0 {
		t.Fatalf("missing postgres rules:\n%s", got)
	}
	if !(ai < di && di < ji) {
		t.Fatal("order must be: admin accept, then drop, then the VPN policy jump")
	}
}

// nft rejects element timeouts of several years ("value too large"); such
// bans are rendered without a timeout and expire through the next reconcile.
func TestLongBanRendersWithoutTimeout(t *testing.T) {
	rs := fullRuleset()
	tenYears := testNow.Add(10 * 365 * 24 * time.Hour)
	month := testNow.Add(30 * 24 * time.Hour)
	rs.Blocked = []BlockedEntry{
		{Prefix: netip.MustParsePrefix("203.0.113.1/32"), Expires: &tenYears},
		{Prefix: netip.MustParsePrefix("203.0.113.2/32"), Expires: &month},
	}
	got, err := Compile(rs, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "elements = { 203.0.113.1, 203.0.113.2 timeout 2592000s }") {
		t.Fatalf("unexpected blocked elements:\n%s", got)
	}
}

func TestUDPForwardOnNetworkListenPortRejected(t *testing.T) {
	rs := fullRuleset()
	rs.Forwards[0].Proto = UDP
	rs.Forwards[0].PublicPort = 51950 // wg2's listen port, outside the legacy range
	if _, err := Compile(rs, testNow); err == nil {
		t.Fatal("a UDP forward must not take a WireGuard listen port")
	}
}

func TestDHCPv6ClientRepliesAccepted(t *testing.T) {
	got, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept`) {
		t.Fatal("DHCPv6 replies must be accepted, or the host loses its IPv6 lease")
	}
}

func TestValidInterfaceName(t *testing.T) {
	for name, want := range map[string]bool{"wg0": true, "ens3": true, "br-1a2b": true, "": false,
		"wg-name-longer-than-15": false, `eth0"`: false} {
		if ValidInterfaceName(name) != want {
			t.Errorf("ValidInterfaceName(%q) != %v", name, want)
		}
	}
}
