package nft

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DroppedSetSize caps the dropped_v4 and dropped_v6 sets; when one is full
// new sources are not recorded (packets are dropped as before).
const DroppedSetSize = 4096

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
	writeLimits(b, rs)
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
	// Node groups (P9a), named by VPN rules.
	groups := append([]Group(nil), rs.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	for _, g := range groups {
		b.set(g.Name, "ipv4_addr", nil, addrElems(g.Members))
	}
	// Limit profiles (P9b): the members, and per-member meters.
	for _, l := range sortedLimits(rs.Limits) {
		b.set(l.Name, "ipv4_addr", nil, addrElems(l.Members))
		if l.UpBytes > 0 {
			meterSet(b, l.Name+"_up")
		}
		if l.DownBytes > 0 {
			meterSet(b, l.Name+"_down")
		}
		if l.MaxConns > 0 {
			// ct count needs a dynamic set without timeouts.
			b.line(1, "set "+l.Name+"_ct {")
			b.line(2, "type ipv4_addr")
			b.line(2, "size "+strconv.Itoa(limitSetSize))
			b.line(2, "flags dynamic")
			b.line(1, "}")
		}
	}
	// Sources of packets the input policy drops, kept for an hour (Live view).
	for _, d := range [][2]string{{"dropped_v4", "ipv4_addr"}, {"dropped_v6", "ipv6_addr"}} {
		b.line(1, "set "+d[0]+" {")
		b.line(2, "type "+d[1])
		b.line(2, "size "+strconv.Itoa(DroppedSetSize))
		b.line(2, "flags dynamic, timeout")
		b.line(2, "timeout 1h")
		b.line(1, "}")
	}
}

func writeInput(b *builder, rs Ruleset) {
	b.line(1, "chain input {")
	b.line(2, "type filter hook input priority filter - 10; policy drop;")
	b.line(2, `iif "lo" accept`)
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	// Port-scoped blocks also cut existing connections, like whole blocks.
	for _, r := range rs.IPRules {
		if r.Action == "block" {
			b.line(2, ipRuleLine(r, "counter drop"))
		}
	}
	b.line(2, "ct state established,related accept")
	b.line(2, "ct state invalid drop")
	b.line(2, "tcp dport @ssh_ports accept")
	b.line(2, "udp dport @wg_ports accept")
	// DHCPv6 replies come from the server's link-local address to a multicast
	// solicit, so conntrack cannot match them as established.
	b.line(2, `ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept comment "dhcpv6 client"`)
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, AdminInterface, joinPorts(AdminPorts)))
	b.line(2, fmt.Sprintf(`iifname { %s } tcp dport { %s } accept`, quoteJoin(vpnInterfaces(rs)), joinPorts(APIPorts)))
	for _, s := range rs.Services {
		for _, l := range serviceLines(s) {
			b.line(2, l)
		}
	}
	// The admin and API ports stay VPN-only even for allowed sources: their
	// VPN accepts are above, so this drop only reaches other interfaces.
	b.line(2, fmt.Sprintf(`tcp dport { %s } counter drop comment "admin ports: VPN only"`,
		joinPorts(append(append([]uint16{}, AdminPorts...), APIPorts...))))
	for _, r := range rs.IPRules {
		if r.Action == "allow" {
			b.line(2, ipRuleLine(r, "accept"))
		}
	}
	b.line(2, "meta l4proto { icmp, ipv6-icmp } accept")
	// Record who reaches the policy drop; a full set only stops recording.
	b.line(2, "update @dropped_v4 { ip saddr }")
	b.line(2, "update @dropped_v6 { ip6 saddr }")
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

// ipRuleLine renders one IPRule with the given verdict, e.g.
// `ip saddr 203.0.113.5 tcp dport { 80, 443 } counter drop comment "ip:x"`.
func ipRuleLine(r IPRule, verdict string) string {
	family := "ip"
	if !r.Prefix.Addr().Is4() {
		family = "ip6"
	}
	parts := []string{family + " saddr " + elemPrefix(r.Prefix.Masked())}
	switch {
	case len(r.Ports) > 0:
		parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Proto, strings.Join(rangeElems(r.Ports), ", ")))
	case r.Proto != "":
		parts = append(parts, "meta l4proto "+string(r.Proto))
	}
	parts = append(parts, verdict, fmt.Sprintf("comment %q", "ip:"+r.ID))
	return strings.Join(parts, " ")
}

func writeForward(b *builder, rs Ruleset) {
	b.line(1, "chain forward {")
	b.line(2, "type filter hook forward priority filter - 10; policy accept;")
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	// Limits also cover connections that already exist.
	if len(rs.Limits) > 0 {
		b.line(2, "jump limits")
	}
	b.line(2, "ct state established,related accept")
	// Docker publishes postgres on all addresses and DNATs it to the
	// container, so it passes forward, not input: the admin VPN keeps access,
	// every other interface (public, LAN, IPv6) loses it.
	b.line(2, fmt.Sprintf(`iifname %q meta l4proto tcp ct original proto-dst 5432 ct status dnat accept comment "admin VPN to docker-published postgres"`, AdminInterface))
	b.line(2, `meta l4proto tcp ct original proto-dst 5432 ct status dnat counter drop comment "docker-published postgres"`)
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
	switch {
	case r.SrcSet != "":
		parts = append(parts, "ip saddr @"+r.SrcSet)
	case r.Src.Bits() != 0:
		parts = append(parts, "ip saddr "+r.Src.Masked().String())
	}
	switch {
	case r.DstSet != "":
		parts = append(parts, "ip daddr @"+r.DstSet)
	case r.Dst.Bits() != 0:
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

// limitSetSize caps the per-member meter sets of one limit profile.
const limitSetSize = 65535

// meterSet declares a per-address rate meter; idle addresses expire.
func meterSet(b *builder, name string) {
	b.line(1, "set "+name+" {")
	b.line(2, "type ipv4_addr")
	b.line(2, "size "+strconv.Itoa(limitSetSize))
	b.line(2, "flags dynamic, timeout")
	b.line(2, "timeout 1m")
	b.line(1, "}")
}

func sortedLimits(limits []Limit) []Limit {
	out := append([]Limit(nil), limits...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// minBurst keeps the bucket (rate+burst) larger than one 64 KiB packet, the
// most GRO merges on the receive path: a smaller bucket would drop every
// merged packet at low rates.
const minBurst = 65536

// limitBurst is the burst above the rate a meter allows. The kernel's bucket
// holds rate+burst bytes, so a burst equal to the rate let a fresh flow send
// twice the rate in its first second (measured: 8 Mbit/s became 10.9 over
// 5 s, and 8.0 once the first 2 s were left out).
func limitBurst(rate uint64) uint64 {
	if b := rate / 4; b > minBurst {
		return b
	}
	return minBurst
}

// writeLimits renders the limits chain (jumped to from forward) and one
// schedule chain per profile with time windows. Rates are policed: packets
// above the rate, after a short burst, are dropped.
func writeLimits(b *builder, rs Ruleset) {
	if len(rs.Limits) == 0 {
		return
	}
	limits := sortedLimits(rs.Limits)
	b.line(1, "chain limits {")
	for _, l := range limits {
		if len(l.Windows) > 0 {
			b.line(2, fmt.Sprintf("ip saddr @%s jump %s_time", l.Name, l.Name))
			b.line(2, fmt.Sprintf("ip daddr @%s jump %s_time", l.Name, l.Name))
		}
		if l.UpBytes > 0 {
			b.line(2, fmt.Sprintf("ip saddr @%[1]s update @%[1]s_up { ip saddr limit rate over %[2]d bytes/second burst %[3]d bytes } counter drop comment %[4]q",
				l.Name, l.UpBytes, limitBurst(l.UpBytes), "limit:"+l.ID+":up"))
		}
		if l.DownBytes > 0 {
			b.line(2, fmt.Sprintf("ip daddr @%[1]s update @%[1]s_down { ip daddr limit rate over %[2]d bytes/second burst %[3]d bytes } counter drop comment %[4]q",
				l.Name, l.DownBytes, limitBurst(l.DownBytes), "limit:"+l.ID+":down"))
		}
		if l.MaxConns > 0 {
			// The count is taken on every packet and only new connections are
			// dropped: each apply replaces the table and empties the set, and
			// the open connections must count again with their next packet.
			b.line(2, fmt.Sprintf("ip saddr @%[1]s add @%[1]s_ct { ip saddr ct count over %[2]d } ct state new counter drop comment %[3]q",
				l.Name, l.MaxConns, "limit:"+l.ID+":conn"))
		}
	}
	b.line(1, "}")
	for _, l := range limits {
		if len(l.Windows) == 0 {
			continue
		}
		b.line(1, "chain "+l.Name+"_time {")
		for _, w := range sortedWindows(l.Windows) {
			b.line(2, fmt.Sprintf("meta day %q meta hour %q-%q return", w.Day.String(), clock(w.From), clock(w.To-1)))
		}
		b.line(2, fmt.Sprintf("counter drop comment %q", "limit:"+l.ID+":schedule"))
		b.line(1, "}")
	}
}

func sortedWindows(in []TimeWindow) []TimeWindow {
	out := append([]TimeWindow(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day < out[j].Day
		}
		return out[i].From < out[j].From
	})
	return out
}

// clock renders seconds since midnight as HH:MM:SS.
func clock(secs int) string {
	return fmt.Sprintf("%02d:%02d:%02d", secs/3600, secs%3600/60, secs%60)
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
			// nft rejects timeouts of several years; longer bans stay in the
			// set without a timeout and are removed by a later reconcile.
			if secs <= maxElementTimeout {
				el += fmt.Sprintf(" timeout %ds", secs)
			}
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	return v4, v6
}

// maxElementTimeout is the longest set-element timeout rendered (365 days);
// nft 1.0.2–1.0.9 reject multi-year values with "value too large".
const maxElementTimeout = 365 * 24 * 3600

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

// vpnInterfaces lists the WireGuard interfaces of NovusGate's networks plus
// the admin interface, sorted, so only real VPN networks get the VPN-only
// exceptions (M5).
func vpnInterfaces(rs Ruleset) []string {
	seen := map[string]bool{AdminInterface: true}
	out := []string{AdminInterface}
	for _, n := range rs.Networks {
		if !seen[n.Interface] {
			seen[n.Interface] = true
			out = append(out, n.Interface)
		}
	}
	sort.Strings(out)
	return out
}

func quoteJoin(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = strconv.Quote(n)
	}
	return strings.Join(q, ", ")
}
