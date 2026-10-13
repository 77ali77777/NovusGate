package nft

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Compile renders rs as an nft script that atomically replaces table
// inet novusgate. The script is valid input for `nft -f` and `nft -c -f`.
// now is used to turn blocked-entry expiry times into remaining timeouts.
func Compile(rs Ruleset, now time.Time) (string, error) {
	if err := Validate(rs); err != nil {
		return "", err
	}
	b := &builder{}
	// Declaring the table first makes the delete succeed on a host where it
	// does not exist yet; the whole file is applied as one transaction.
	b.line(0, "table inet "+TableName)
	b.line(0, "delete table inet "+TableName)
	b.line(0, "table inet "+TableName+" {")
	writeSets(b, rs, now)
	writeInput(b, rs)
	writeForward(b, rs)
	writeVPNPolicy(b, rs)
	writeNAT(b, rs)
	b.line(0, "}")
	return b.String(), nil
}

type builder struct{ strings.Builder }

func (b *builder) line(indent int, s string) {
	b.WriteString(strings.Repeat("\t", indent))
	b.WriteString(s)
	b.WriteString("\n")
}

func (b *builder) set(name, typ string, flags []string, elems []string) {
	b.line(1, "set "+name+" {")
	b.line(2, "type "+typ)
	if len(flags) > 0 {
		b.line(2, "flags "+strings.Join(flags, ", "))
	}
	if len(elems) > 0 {
		b.line(2, "elements = { "+strings.Join(elems, ", ")+" }")
	}
	b.line(1, "}")
}

func writeSets(b *builder, rs Ruleset, now time.Time) {
	b.set("ssh_ports", "inet_service", nil, portElems(rs.SSHPorts))
	b.set("wg_ports", "inet_service", []string{"interval"}, rangeElems(wireGuardRanges(rs)))
	v4, v6 := blockedElems(rs.Blocked, now)
	b.set("blocked_v4", "ipv4_addr", []string{"interval", "timeout"}, v4)
	b.set("blocked_v6", "ipv6_addr", []string{"interval", "timeout"}, v6)
	b.set("egress_v4", "ipv4_addr", nil, addrElems(rs.Egress))
}

func writeInput(b *builder, rs Ruleset) {
	b.line(1, "chain input {")
	b.line(2, "type filter hook input priority filter - 10; policy drop;")
	b.line(2, `iif "lo" accept`)
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	b.line(2, "ct state established,related accept")
	b.line(2, "ct state invalid drop")
	b.line(2, "tcp dport @ssh_ports accept")
	b.line(2, "udp dport @wg_ports accept")
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, AdminInterface, joinPorts(AdminPorts)))
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, VPNInterfacePattern, joinPorts(APIPorts)))
	for _, s := range rs.Services {
		for _, l := range serviceLines(s) {
			b.line(2, l)
		}
	}
	b.line(2, "meta l4proto { icmp, ipv6-icmp } accept")
	b.line(2, `counter comment "default drop"`)
	b.line(1, "}")
}

func serviceLines(s Service) []string {
	var prefix string
	if s.Interface != "" {
		prefix = fmt.Sprintf("iifname %q ", s.Interface)
	}
	tail := fmt.Sprintf("%s dport %s accept comment %q", s.Proto, s.Ports, "svc:"+s.ID)
	if len(s.Sources) == 0 {
		return []string{prefix + tail}
	}
	var v4, v6 []string
	for _, p := range s.Sources {
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	var lines []string
	if len(v4) > 0 {
		lines = append(lines, prefix+"ip saddr { "+strings.Join(v4, ", ")+" } "+tail)
	}
	if len(v6) > 0 {
		lines = append(lines, prefix+"ip6 saddr { "+strings.Join(v6, ", ")+" } "+tail)
	}
	return lines
}

func writeForward(b *builder, rs Ruleset) {
	b.line(1, "chain forward {")
	b.line(2, "type filter hook forward priority filter - 10; policy accept;")
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	b.line(2, "ct state established,related accept")
	// Docker publishes postgres on all addresses and its DNAT bypasses the
	// input chain; only the admin VPN may reach it.
	b.line(2, fmt.Sprintf(`iifname %q meta l4proto tcp ct original proto-dst 5432 counter drop comment "docker-published postgres"`, rs.EgressInterface))
	b.line(2, fmt.Sprintf(`iifname %q jump vpn_policy`, VPNInterfacePattern))
	b.line(2, fmt.Sprintf(`oifname %q ct status dnat accept`, VPNInterfacePattern))
	b.line(2, fmt.Sprintf(`oifname %q counter drop`, VPNInterfacePattern))
	b.line(1, "}")
}

func writeVPNPolicy(b *builder, rs Ruleset) {
	b.line(1, "chain vpn_policy {")
	for _, r := range rs.VPNRules {
		b.line(2, vpnRuleLine(r))
	}
	// Peers of the same network have always been able to talk to each other.
	for _, n := range sortedNetworks(rs.Networks) {
		b.line(2, fmt.Sprintf(`iifname %q oifname %q accept`, n.Interface, n.Interface))
	}
	b.line(2, fmt.Sprintf(`oifname %q ip saddr @egress_v4 accept`, rs.EgressInterface))
	b.line(2, `counter drop comment "vpn default drop"`)
	b.line(1, "}")
}

func vpnRuleLine(r VPNRule) string {
	var parts []string
	if r.Src.Bits() != 0 {
		parts = append(parts, "ip saddr "+r.Src.Masked().String())
	}
	if r.Dst.Bits() != 0 {
		parts = append(parts, "ip daddr "+r.Dst.Masked().String())
	}
	switch r.Proto {
	case TCP, UDP:
		if len(r.Ports) > 0 {
			parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Proto, strings.Join(rangeElems(r.Ports), ", ")))
		} else {
			parts = append(parts, "meta l4proto "+string(r.Proto))
		}
	case ICMP:
		parts = append(parts, "meta l4proto icmp")
	}
	parts = append(parts, "counter", r.Action, fmt.Sprintf("comment %q", "rule:"+r.ID))
	return strings.Join(parts, " ")
}

func writeNAT(b *builder, rs Ruleset) {
	b.line(1, "chain prerouting {")
	b.line(2, "type nat hook prerouting priority dstnat; policy accept;")
	for _, f := range rs.Forwards {
		b.line(2, fmt.Sprintf(`iifname %q %s dport %d dnat ip to %s:%d comment %q`,
			rs.EgressInterface, f.Proto, f.PublicPort, f.TargetIP, f.TargetPort, "fwd:"+f.ID))
	}
	b.line(1, "}")
	b.line(1, "chain postrouting {")
	b.line(2, "type nat hook postrouting priority srcnat; policy accept;")
	for _, f := range rs.Forwards {
		n, _ := networkFor(rs.Networks, f.TargetIP)
		// Masquerade so the node replies through the hub: its AllowedIPs only
		// cover VPN subnets, not the internet client's address.
		b.line(2, fmt.Sprintf(`ip daddr %s oifname %q %s dport %d ct status dnat masquerade comment %q`,
			f.TargetIP, n.Interface, f.Proto, f.TargetPort, "fwd:"+f.ID))
	}
	b.line(2, fmt.Sprintf(`oifname %q ip saddr @egress_v4 masquerade`, rs.EgressInterface))
	b.line(1, "}")
}

func networkFor(networks []VPNNetwork, ip netip.Addr) (VPNNetwork, bool) {
	for _, n := range networks {
		if n.CIDR.Contains(ip) {
			return n, true
		}
	}
	return VPNNetwork{}, false
}

func sortedNetworks(networks []VPNNetwork) []VPNNetwork {
	out := append([]VPNNetwork(nil), networks...)
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

func portElems(ports []uint16) []string {
	seen := map[uint16]bool{}
	var sorted []int
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			sorted = append(sorted, int(p))
		}
	}
	sort.Ints(sorted)
	out := make([]string, len(sorted))
	for i, p := range sorted {
		out[i] = fmt.Sprintf("%d", p)
	}
	return out
}

func joinPorts(ports []uint16) string { return strings.Join(portElems(ports), ", ") }

// wireGuardRanges merges the legacy installer range with every network's
// listen port, so networks beyond 51900 stay reachable.
func wireGuardRanges(rs Ruleset) []PortRange {
	ranges := []PortRange{LegacyWireGuardRange}
	for _, n := range rs.Networks {
		if n.ListenPort != 0 {
			ranges = append(ranges, PortRange{From: n.ListenPort, To: n.ListenPort})
		}
	}
	return mergeRanges(ranges)
}

// mergeRanges returns sorted, non-overlapping, non-adjacent ranges; nft
// rejects overlapping elements in interval sets.
func mergeRanges(in []PortRange) []PortRange {
	rs := append([]PortRange(nil), in...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].From < rs[j].From })
	var out []PortRange
	for _, r := range rs {
		if n := len(out); n > 0 && uint32(r.From) <= uint32(out[n-1].To)+1 {
			if r.To > out[n-1].To {
				out[n-1].To = r.To
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func rangeElems(ranges []PortRange) []string {
	merged := mergeRanges(ranges)
	out := make([]string, len(merged))
	for i, r := range merged {
		out[i] = r.String()
	}
	return out
}

// blockedElems drops expired entries and entries covered by a broader prefix
// (interval sets reject overlaps), then renders the remaining timeouts.
func blockedElems(entries []BlockedEntry, now time.Time) (v4, v6 []string) {
	var active []BlockedEntry
	for _, e := range entries {
		if e.Expires != nil && !e.Expires.After(now) {
			continue
		}
		e.Prefix = e.Prefix.Masked()
		active = append(active, e)
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].Prefix.Bits() != active[j].Prefix.Bits() {
			return active[i].Prefix.Bits() < active[j].Prefix.Bits()
		}
		return active[i].Prefix.Addr().Less(active[j].Prefix.Addr())
	})
	var kept []BlockedEntry
	for _, e := range active {
		covered := false
		for _, k := range kept {
			if k.Prefix.Addr().Is4() == e.Prefix.Addr().Is4() && k.Prefix.Contains(e.Prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, e)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Prefix.Addr().Less(kept[j].Prefix.Addr()) })
	for _, e := range kept {
		el := elemPrefix(e.Prefix)
		if e.Expires != nil {
			secs := int64(math.Ceil(e.Expires.Sub(now).Seconds()))
			el += fmt.Sprintf(" timeout %ds", secs)
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	return v4, v6
}

// elemPrefix renders a host prefix as a bare address, as nft lists it.
func elemPrefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func addrElems(addrs []netip.Addr) []string {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	s := make([]string, len(out))
	for i, a := range out {
		s[i] = a.String()
	}
	return s
}
