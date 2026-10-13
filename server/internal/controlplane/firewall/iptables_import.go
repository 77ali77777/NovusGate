package firewall

import (
	"net/netip"
	"strings"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// ParseIptablesInput converts the panel-made rules in `iptables -S INPUT`
// output into engine records. Installer rules (interface-bound, conntrack,
// loopback, ICMP, the WireGuard range, SSH ports, unsourced DROPs) and chains
// owned by other tools (fail2ban) are skipped and returned for logging.
func ParseIptablesInput(out string, sshPorts []uint16) ([]*models.FirewallService, []*models.FirewallIPRule, []string) {
	var services []*models.FirewallService
	var ipRules []*models.FirewallIPRule
	var skipped []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		r := parseIptablesRule(line)
		switch {
		case r.iface != "" || r.module == "state" || r.module == "conntrack" || r.proto == "icmp":
			skipped = append(skipped, line)
		case r.target != "ACCEPT" && r.target != "DROP":
			skipped = append(skipped, line) // e.g. -j f2b-sshd, -j REJECT
		case r.proto == "udp" && r.source == "" && inWireGuardRange(r.ports):
			skipped = append(skipped, line) // installer or reset WireGuard range
		case r.target == "DROP" && r.source == "":
			skipped = append(skipped, line) // installer safety-net drops
		case r.target == "ACCEPT" && r.source == "" && r.ports == "":
			skipped = append(skipped, line)
		case r.target == "ACCEPT" && r.ports != "" && (r.proto == "tcp" || r.proto == "udp"):
			if r.source == "" && r.proto == "tcp" && isSSHOnly(r.ports, sshPorts) {
				skipped = append(skipped, line)
				continue
			}
			for _, pr := range strings.Split(r.ports, ",") {
				from, to := splitRange(pr)
				svc := &models.FirewallService{Protocol: r.proto, Sources: []string{}, Comment: "imported from iptables"}
				svc.PortFrom, svc.PortTo = from, to
				if r.source != "" {
					svc.Sources = []string{r.source}
				}
				if svc.PortFrom > 0 {
					services = append(services, svc)
				}
			}
		case r.source != "":
			action := "allow"
			if r.target == "DROP" {
				action = "block"
			}
			rule := &models.FirewallIPRule{Action: action, Prefix: r.source, Origin: "import", Comment: "imported from iptables"}
			if r.ports != "" && (r.proto == "tcp" || r.proto == "udp") {
				rule.Protocol, rule.Ports = r.proto, r.ports
			}
			ipRules = append(ipRules, rule)
		default:
			skipped = append(skipped, line)
		}
	}
	return services, ipRules, skipped
}

type iptablesRule struct {
	source, proto, ports, target, iface, module string
}

func parseIptablesRule(line string) iptablesRule {
	var r iptablesRule
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "-s":
			r.source = canonicalPrefix(f[i+1])
		case "-p":
			r.proto = f[i+1]
		case "--dport", "--dports":
			r.ports = strings.ReplaceAll(f[i+1], ":", "-")
		case "-j":
			r.target = f[i+1]
		case "-i":
			r.iface = f[i+1]
		case "-m":
			if f[i+1] == "state" || f[i+1] == "conntrack" {
				r.module = f[i+1]
			}
		}
	}
	return r
}

func canonicalPrefix(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return s
}

func splitRange(s string) (int, int) {
	ranges, err := ParsePorts(s)
	if err != nil || len(ranges) != 1 {
		return 0, 0
	}
	return int(ranges[0].From), int(ranges[0].To)
}

// inWireGuardRange reports whether every port lies in 51820-51900, the range
// setup-firewall.sh (51820:51900) and the legacy reset (51820:51830) open.
func inWireGuardRange(ports string) bool {
	ranges, err := ParsePorts(ports)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if r.From < 51820 || r.To > 51900 {
			return false
		}
	}
	return true
}

func isSSHOnly(ports string, sshPorts []uint16) bool {
	for _, p := range strings.Split(ports, ",") {
		from, to := splitRange(p)
		if from == 0 || from != to {
			return false
		}
		found := false
		for _, s := range sshPorts {
			if int(s) == from {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
