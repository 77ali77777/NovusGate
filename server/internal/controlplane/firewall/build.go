// Package firewall turns stored NovusGate state into the nft engine model.
package firewall

import (
	"fmt"
	"net/netip"
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
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
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
	var out []nft.VPNRule
	var errs []error
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		src, err := endpoint(r.SourceType, r.SourceNetworkID, r.SourceNodeID, r.SourceIP, networks, nodes)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s source: %v", r.Name, err))
			continue
		}
		dst, err := endpoint(r.DestType, r.DestNetworkID, r.DestNodeID, r.DestIP, networks, nodes)
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
		out = append(out, nft.VPNRule{ID: r.ID, Src: src, Dst: dst, Proto: proto, Ports: ports, Action: r.Action})
	}
	return out, errs
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
