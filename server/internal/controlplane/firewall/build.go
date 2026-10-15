// Package firewall turns stored NovusGate state into the nft engine model.
package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// NetworksFromModels converts stored networks; networks without an interface
// (never brought up) are skipped and reported.
func NetworksFromModels(networks []*models.Network) ([]nft.VPNNetwork, []error) {
	var out []nft.VPNNetwork
	var errs []error
	for _, n := range networks {
		if n.InterfaceName == "" {
			errs = append(errs, fmt.Errorf("network %s has no interface", n.Name))
			continue
		}
		if !nft.ValidInterfaceName(n.InterfaceName) {
			errs = append(errs, fmt.Errorf("network %s: unsupported interface name %q", n.Name, n.InterfaceName))
			continue
		}
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			errs = append(errs, fmt.Errorf("network %s: %v", n.Name, err))
			continue
		}
		if prefix, err = ipv4Prefix(prefix); err != nil {
			errs = append(errs, fmt.Errorf("network %s: %v", n.Name, err))
			continue
		}
		port := n.ListenPort
		if port < 0 || port > 65535 {
			port = 0
		}
		out = append(out, nft.VPNNetwork{Interface: n.InterfaceName, CIDR: prefix.Masked(), ListenPort: uint16(port)})
	}
	return out, errs
}

// VPNRulesFromModels converts stored VPN rules in their stored order.
// Disabled rules are skipped; a rule that cannot be converted is reported
// and skipped so one bad rule never blocks the rest.
func VPNRulesFromModels(rules []*models.VPNFirewallRule, networks map[string]*models.Network, nodes map[string]*models.Node) ([]nft.VPNRule, []error) {
	out, _, errs := vpnRulesWithGroups(rules, networks, nodes, nil)
	return out, errs
}

// vpnRulesWithGroups is VPNRulesFromModels with group endpoints (P9a): a
// group becomes the set grp_<n> (n: the group's place in ID order) and the
// sets the rules use are returned with their members' addresses.
func vpnRulesWithGroups(rules []*models.VPNFirewallRule, networks map[string]*models.Network, nodes map[string]*models.Node,
	groups []*models.NodeGroup) ([]nft.VPNRule, []nft.Group, []error) {
	byID := map[string]*models.NodeGroup{}
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		byID[g.ID] = g
		ids = append(ids, g.ID)
	}
	sort.Strings(ids)
	setName := map[string]string{}
	for i, id := range ids {
		setName[id] = setName2("grp", byID[id].SetNo, i)
	}
	used := map[string]nft.Group{}
	// end resolves one side of a rule to a set name or a prefix.
	end := func(kind string, groupID, networkID, nodeID *string, custom string) (string, netip.Prefix, error) {
		if kind == "group" {
			if groupID == nil || byID[*groupID] == nil {
				return "", netip.Prefix{}, fmt.Errorf("group not found")
			}
			name := setName[*groupID]
			if _, ok := used[name]; !ok {
				g := nft.Group{Name: name}
				for _, m := range byID[*groupID].Members {
					if a, err := netip.ParseAddr(m.VirtualIP); err == nil && a.Unmap().Is4() {
						g.Members = append(g.Members, a.Unmap())
					}
				}
				used[name] = g
			}
			return name, netip.Prefix{}, nil
		}
		p, err := endpoint(kind, networkID, nodeID, custom, networks, nodes)
		if err != nil {
			return "", p, err
		}
		p, err = ipv4Prefix(p)
		return "", p, err
	}
	var out []nft.VPNRule
	var errs []error
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		srcSet, src, err := end(r.SourceType, r.SourceGroupID, r.SourceNetworkID, r.SourceNodeID, r.SourceIP)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s source: %v", r.Name, err))
			continue
		}
		dstSet, dst, err := end(r.DestType, r.DestGroupID, r.DestNetworkID, r.DestNodeID, r.DestIP)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s destination: %v", r.Name, err))
			continue
		}
		proto := nft.Protocol(r.Protocol)
		if proto == "" {
			proto = nft.All
		}
		var ports []nft.PortRange
		if r.Port != "" && (proto == nft.TCP || proto == nft.UDP) {
			if ports, err = ParsePorts(r.Port); err != nil {
				errs = append(errs, fmt.Errorf("rule %s: %v", r.Name, err))
				continue
			}
		}
		out = append(out, nft.VPNRule{ID: r.ID, Src: src, Dst: dst, SrcSet: srcSet, DstSet: dstSet, Proto: proto, Ports: ports, Action: r.Action})
	}
	sets := make([]nft.Group, 0, len(used))
	for _, g := range used {
		sets = append(sets, g)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Name < sets[j].Name })
	return out, sets, errs
}

func endpoint(kind string, networkID, nodeID *string, custom string, networks map[string]*models.Network, nodes map[string]*models.Node) (netip.Prefix, error) {
	switch kind {
	case "any":
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	case "network":
		if networkID == nil || networks[*networkID] == nil {
			return netip.Prefix{}, fmt.Errorf("network not found")
		}
		p, err := netip.ParsePrefix(networks[*networkID].CIDR)
		return p.Masked(), err
	case "node":
		if nodeID == nil || nodes[*nodeID] == nil {
			return netip.Prefix{}, fmt.Errorf("node not found")
		}
		addr, ok := netip.AddrFromSlice(nodes[*nodeID].VirtualIP)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("node has no address")
		}
		return netip.PrefixFrom(addr.Unmap(), 32), nil
	case "custom":
		if strings.Contains(custom, "/") {
			p, err := netip.ParsePrefix(custom)
			return p.Masked(), err
		}
		addr, err := netip.ParseAddr(custom)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("unknown endpoint type %q", kind)
}

// ipv4Prefix unmaps IPv4-mapped IPv6 prefixes (::ffff:a.b.c.d) and rejects
// real IPv6: VPN subnets and their rules are IPv4 only.
func ipv4Prefix(p netip.Prefix) (netip.Prefix, error) {
	addr := p.Addr()
	if addr.Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %s is too wide", p)
		}
		return netip.PrefixFrom(addr.Unmap(), bits).Masked(), nil
	}
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("IPv6 %s is not supported for VPN networks and rules", p)
	}
	return p, nil
}

// ParsePorts accepts "22", "80,443" and ranges written "8000-9000" or "8000:9000".
func ParsePorts(s string) ([]nft.PortRange, error) {
	var out []nft.PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		sep := strings.IndexAny(part, "-:")
		fromS, toS := part, part
		if sep > 0 {
			fromS, toS = part[:sep], part[sep+1:]
		}
		from, err1 := strconv.Atoi(fromS)
		to, err2 := strconv.Atoi(toS)
		if err1 != nil || err2 != nil || from < 1 || to > 65535 || to < from {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		out = append(out, nft.PortRange{From: uint16(from), To: uint16(to)})
	}
	return out, nil
}

// setName2 names a group or limit set by its stored number, which never
// changes, so adding a group or profile does not rename the others' sets.
// Sources without numbers (tests, old rows) fall back to 900000+index.
func setName2(prefix string, setNo, index int) string {
	if setNo > 0 && setNo < 900000 {
		return fmt.Sprintf("%s_%d", prefix, setNo)
	}
	return fmt.Sprintf("%s_%d", prefix, 900000+index)
}
