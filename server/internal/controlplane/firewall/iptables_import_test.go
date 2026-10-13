package firewall

import (
	"strings"
	"testing"
)

// `iptables -S INPUT` after setup-firewall.sh, panel actions and fail2ban.
const iptablesInput = `-P INPUT DROP
-A INPUT -s 198.51.100.9/32 -j DROP
-A INPUT -s 203.0.113.7/32 -p tcp -m multiport --dports 80,443 -j DROP
-A INPUT -s 192.0.2.0/24 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT
-A INPUT -p udp -m udp --dport 51820:51900 -j ACCEPT
-A INPUT -i wg0 -p tcp -m tcp --dport 3007 -j ACCEPT
-A INPUT -i wg+ -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3007 -j DROP
-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 8443 -j ACCEPT
-A INPUT -p udp -m udp --dport 60000:60010 -j ACCEPT
`

func TestParseIptablesInput(t *testing.T) {
	services, ipRules, skipped := ParseIptablesInput(iptablesInput, []uint16{22, 2222})

	if len(services) != 3 {
		t.Fatalf("services = %d, want 3 (443, 8443 from 203.0.113.0/24, udp 60000-60010)", len(services))
	}
	if s := services[0]; s.Protocol != "tcp" || s.PortFrom != 443 || len(s.Sources) != 0 {
		t.Fatalf("open port 443: %+v", s)
	}
	if s := services[1]; s.PortFrom != 8443 || len(s.Sources) != 1 || s.Sources[0] != "203.0.113.0/24" {
		t.Fatalf("sourced port: %+v", s)
	}
	if s := services[2]; s.Protocol != "udp" || s.PortFrom != 60000 || s.PortTo != 60010 {
		t.Fatalf("udp range opened from the panel: %+v", s)
	}

	if len(ipRules) != 3 {
		t.Fatalf("ip rules = %d, want 3", len(ipRules))
	}
	if r := ipRules[0]; r.Action != "block" || r.Prefix != "198.51.100.9/32" || r.Ports != "" || r.Origin != "import" {
		t.Fatalf("whole block: %+v", r)
	}
	if r := ipRules[1]; r.Action != "block" || r.Protocol != "tcp" || r.Ports != "80,443" {
		t.Fatalf("port block: %+v", r)
	}
	if r := ipRules[2]; r.Action != "allow" || r.Prefix != "192.0.2.0/24" {
		t.Fatalf("allow: %+v", r)
	}

	for _, must := range []string{"f2b-sshd", "-i lo", "RELATED,ESTABLISHED", "--dport 22 -j ACCEPT",
		"--dport 2222 -j ACCEPT", "51820:51900", "-i wg0", "--dport 3007 -j DROP", "icmp"} {
		found := false
		for _, s := range skipped {
			if strings.Contains(s, must) {
				found = true
			}
		}
		if !found {
			t.Errorf("installer/foreign rule %q must be skipped", must)
		}
	}
}
