package rest

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// VLAN-style access (plan 2026-10-19, M1): a device's config routes every
// VPN network, whatever the rules say. Who may reach whom is decided by the
// hub's firewall alone (nftables: table inet novusgate; iptables:
// NOVUSGATE-VPN, with networks apart by default in both). So a rule works
// at once and in both directions of a connection (replies are routed back),
// and no device needs a new config when rules change. A device needs one
// only when the routes themselves change: a new network, its tunnel mode,
// an address range outside the VPN that a rule names.

// routePlan holds what every device's config routes.
type routePlan struct {
	cidr   map[string]string // network ID -> CIDR
	all    []string          // every VPN network CIDR, sorted
	custom []string          // ranges outside the VPN that enabled accept rules name, sorted
	full   map[string]bool   // nodes that use the hub as internet exit
}

// loadRoutePlan reads the networks, the rules' outside ranges and the
// full-tunnel nodes. Only the network list is required: without the rules
// or the exit set the plan routes the VPN networks (and logs why).
func (s *Server) loadRoutePlan(ctx context.Context) (routePlan, error) {
	p := routePlan{cidr: map[string]string{}, full: map[string]bool{}}
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return p, fmt.Errorf("list networks: %w", err)
	}
	vpn := map[string]bool{}
	for _, n := range networks {
		p.cidr[n.ID] = n.CIDR
		if !vpn[n.CIDR] {
			vpn[n.CIDR] = true
			p.all = append(p.all, n.CIDR)
		}
	}
	sort.Strings(p.all)

	if rules, err := s.store.ListVPNFirewallRules(ctx); err != nil {
		slog.Warn("config routes: VPN rules not read; outside address ranges are not routed", "error", err)
	} else {
		seen := map[string]bool{}
		for _, r := range rules {
			if !r.Enabled || r.Action != "accept" {
				continue
			}
			// Both ends: a range that reaches a device needs the reply routed.
			for _, ip := range []string{customIP(r.SourceType, r.SourceIP), customIP(r.DestType, r.DestIP)} {
				if ip != "" && !vpn[ip] && !seen[ip] {
					seen[ip] = true
					p.custom = append(p.custom, ip)
				}
			}
		}
		sort.Strings(p.custom)
	}

	if ids, err := s.store.ListEgressNodeIDs(ctx); err != nil {
		slog.Warn("config routes: full tunnel state not read; configs route the VPN networks only", "error", err)
	} else {
		for _, id := range ids {
			p.full[id] = true
		}
	}
	return p, nil
}

func customIP(kind, ip string) string {
	if kind != "custom" {
		return ""
	}
	return strings.TrimSpace(ip)
}

// allowedIPs is the AllowedIPs of a node's config: everything for full
// tunnel, else its own network first, the other VPN networks, then the
// outside ranges the rules name.
func (p routePlan) allowedIPs(n *models.Node) string {
	if p.full[n.ID] {
		return "0.0.0.0/0"
	}
	own := p.cidr[n.NetworkID]
	out := []string{}
	if own != "" {
		out = append(out, own)
	}
	for _, c := range p.all {
		if c != own {
			out = append(out, c)
		}
	}
	out = append(out, p.custom...)
	return strings.Join(out, ", ")
}

// nodeRouting returns the AllowedIPs and DNS of a node's config. DNS is the
// network's client DNS; without one, full tunnel uses fullTunnelDNS (names
// resolve over the tunnel) and split tunnel has none.
func (s *Server) nodeRouting(ctx context.Context, node *models.Node, network *models.Network) (string, string) {
	dns := ""
	if network != nil {
		dns = network.ClientDNS
	}
	p, err := s.loadRoutePlan(ctx)
	if err != nil {
		slog.Warn("config routes: plan not read; the config routes the node's own network", "node", node.ID, "error", err)
		if network != nil {
			return network.CIDR, dns
		}
		return "", dns
	}
	allowed := p.allowedIPs(node)
	if allowed == "0.0.0.0/0" && dns == "" {
		dns = fullTunnelDNS
	}
	return allowed, dns
}

// recordConfigRoutes keeps the routes of the config just handed out; a
// failure only leaves the "config outdated" mark on.
func (s *Server) recordConfigRoutes(ctx context.Context, nodeID, routes string) {
	if err := s.store.SetNodeConfigRoutes(ctx, nodeID, routes); err != nil {
		slog.Warn("config routes not recorded", "node", nodeID, "error", err)
	}
}

// markOutdated sets ConfigOutdated on nodes whose last handed-out config no
// longer has the routes they need.
func (s *Server) markOutdated(ctx context.Context, nodes ...*models.Node) {
	p, err := s.loadRoutePlan(ctx)
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n != nil {
			n.ConfigOutdated = n.ConfigRoutes != p.allowedIPs(n)
		}
	}
}
