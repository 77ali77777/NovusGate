package rest

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// VLAN-style access (plan 2026-10-19, M1): a device's config routes every
// VPN network, whatever the rules say. Who may reach whom is decided by the
// hub's firewall alone (nftables: table inet novusgate; iptables:
// NOVUSGATE-VPN, with networks apart by default in both). So a rule works
// at once and in both directions of a connection (replies are routed back),
// and no device needs a new config when rules change. Since P1 of
// server-side routing the config routes one address pool and networks are
// made inside it (pool.go), so a new network needs none either. A device
// needs one only when its routes change: its tunnel mode, the pool, an
// address range outside the pool that a rule names.

// routePlan holds what every device's config routes.
type routePlan struct {
	cidr   map[string]string // network ID -> CIDR
	all    []string          // every VPN network CIDR, sorted
	custom []customRoute     // ranges outside the VPN that enabled accept rules name
	full   map[string]bool   // nodes that use the hub as internet exit
	pool   netip.Prefix      // the address pool every config routes (invalid: not read)
	host   string            // the endpoint host configs name ("" keeps each network's endpoint)
	nets   map[string]*models.Network
}

// loadRoutePlan reads the networks, the rules' outside ranges and the
// full-tunnel nodes. Only the network list is required: without the rules
// or the exit set the plan routes the VPN networks (and logs why).
func (s *Server) loadRoutePlan(ctx context.Context) (routePlan, error) {
	p := routePlan{cidr: map[string]string{}, full: map[string]bool{}, nets: map[string]*models.Network{}}
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return p, fmt.Errorf("list networks: %w", err)
	}
	vpn := map[string]bool{}
	for _, n := range networks {
		p.nets[n.ID] = n
		p.cidr[n.ID] = n.CIDR
		if !vpn[n.CIDR] {
			vpn[n.CIDR] = true
			p.all = append(p.all, n.CIDR)
		}
	}
	sort.Strings(p.all)
	if p.pool, err = s.vpnPool(ctx); err != nil {
		slog.Warn("config routes: address pool not read; configs name each network", "error", err)
	}
	if p.host, err = s.store.VPNEndpointHost(ctx); err != nil {
		slog.Warn("config routes: endpoint host not read; configs use each network's endpoint", "error", err)
	}

	if rules, err := s.store.ListVPNFirewallRules(ctx); err != nil {
		slog.Warn("config routes: VPN rules not read; outside address ranges are not routed", "error", err)
	} else {
		groups := map[string]map[string]bool{} // group ID -> member node IDs
		members := func(id *string) map[string]bool {
			if id == nil {
				return nil
			}
			if m, ok := groups[*id]; ok {
				return m
			}
			m := map[string]bool{}
			if g, err := s.store.GetNodeGroup(ctx, *id); err != nil {
				slog.Warn("config routes: group not read", "group", *id, "error", err)
			} else if g != nil {
				for _, x := range g.Members {
					m[x.NodeID] = true
				}
			}
			groups[*id] = m
			return m
		}
		for _, r := range rules {
			if !r.Enabled || r.Action != "accept" {
				continue
			}
			// A range on one end is routed by the devices on the other end:
			// they start connections to it, or answer connections from it.
			if ip := customIP(r.DestType, r.DestIP); ip != "" && !vpn[ip] {
				p.custom = append(p.custom, customRoute{cidr: ip, kind: r.SourceType, network: deref(r.SourceNetworkID),
					node: deref(r.SourceNodeID), members: members(r.SourceGroupID)})
			}
			if ip := customIP(r.SourceType, r.SourceIP); ip != "" && !vpn[ip] {
				p.custom = append(p.custom, customRoute{cidr: ip, kind: r.DestType, network: deref(r.DestNetworkID),
					node: deref(r.DestNodeID), members: members(r.DestGroupID)})
			}
		}
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

// customRoute is an outside range and the rule end that routes it.
type customRoute struct {
	cidr    string
	kind    string          // any, network, node, group (custom: no device)
	network string          // kind network
	node    string          // kind node
	members map[string]bool // kind group: member node IDs
}

// covers says whether device n is on the routing end of the rule.
func (c customRoute) covers(n *models.Node) bool {
	switch c.kind {
	case "any":
		return true
	case "network":
		return n.NetworkID == c.network
	case "node":
		return n.ID == c.node
	case "group":
		return c.members[n.ID]
	}
	return false
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func customIP(kind, ip string) string {
	if kind != "custom" {
		return ""
	}
	return strings.TrimSpace(ip)
}

// allowedIPs is the AllowedIPs of a node's config: everything for full
// tunnel, else the address pool, the VPN networks outside it (made before
// the pool; its own first), then the outside ranges of the rules whose
// other end covers the device.
func (p routePlan) allowedIPs(n *models.Node) string {
	if p.full[n.ID] {
		return "0.0.0.0/0"
	}
	// A hub reached at an address inside the pool would get its own
	// handshakes routed into the tunnel: such configs name the networks.
	if p.pool.IsValid() && p.endpointInPool(n) {
		q := p
		q.pool = netip.Prefix{}
		return q.allowedIPs(n)
	}
	own := p.cidr[n.NetworkID]
	out := []string{}
	if p.pool.IsValid() {
		out = append(out, p.pool.String())
	}
	if own != "" && !p.inPool(own) {
		out = append(out, own)
	}
	for _, c := range p.all {
		if c != own && !p.inPool(c) {
			out = append(out, c)
		}
	}
	var custom []string
	seen := map[string]bool{}
	for _, c := range p.custom {
		if !seen[c.cidr] && !p.inPool(c.cidr) && c.covers(n) {
			seen[c.cidr] = true
			custom = append(custom, c.cidr)
		}
	}
	sort.Strings(custom)
	return strings.Join(append(out, custom...), ", ")
}

// endpointInPool: the node's network is reached at an IP inside the pool.
// A name cannot be judged here; the settings refuse an IP inside the pool.
func (p routePlan) endpointInPool(n *models.Node) bool {
	nw := p.nets[n.NetworkID]
	if nw == nil {
		return false
	}
	host := endpointOf(p.host, nw)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	return err == nil && p.pool.Contains(a.Unmap())
}

// inPool: cidr lies wholly inside the pool, which the config already routes.
func (p routePlan) inPool(cidr string) bool {
	c, err := netip.ParsePrefix(cidr)
	if err != nil || !p.pool.IsValid() {
		return false
	}
	return p.pool.Bits() <= c.Bits() && p.pool.Contains(c.Addr())
}

// endpointOf is the endpoint a network's configs name (P2 of server-side
// routing): the configured host with the network's port, else the stored
// endpoint, else WG_SERVER_ENDPOINT with the port.
func endpointOf(host string, n *models.Network) string {
	port := n.ListenPort
	if port == 0 {
		port = wireguard.DefaultServerPort
	}
	if host != "" {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	if n.ServerEndpoint != "" {
		return n.ServerEndpoint
	}
	return fmt.Sprintf("%s:%d", wireguard.GetServerEndpoint(), port)
}

// nodeEndpoint is the endpoint for a config of network n.
func (s *Server) nodeEndpoint(ctx context.Context, n *models.Network) string {
	host, err := s.store.VPNEndpointHost(ctx)
	if err != nil {
		slog.Warn("config endpoint: host not read; the network's endpoint is used", "error", err)
		host = ""
	}
	return endpointOf(host, n)
}

// configRecord is what a handed-out config is remembered by: its routes,
// the endpoint and the DNS server it names. A change of any marks it
// outdated.
func configRecord(allowed, endpoint, dns string) string {
	return allowed + " @ " + endpoint + " # " + dns
}

// nodeRouting returns the AllowedIPs and DNS of a node's config. DNS is the
// network's client DNS; without one, full tunnel uses fullTunnelDNS (names
// resolve over the tunnel) and split tunnel has none.
func (s *Server) nodeRouting(ctx context.Context, node *models.Node, network *models.Network) (string, string) {
	p, err := s.loadRoutePlan(ctx)
	if err != nil {
		slog.Warn("config routes: plan not read; the config routes the node's own network", "node", node.ID, "error", err)
		if network != nil {
			return network.CIDR, s.configDNS(network, network.CIDR)
		}
		return "", ""
	}
	allowed := p.allowedIPs(node)
	return allowed, s.configDNS(network, allowed)
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
			endpoint := ""
			nw := p.nets[n.NetworkID]
			if nw != nil {
				endpoint = endpointOf(p.host, nw)
			}
			allowed := p.allowedIPs(n)
			n.ConfigOutdated = n.ConfigRoutes != configRecord(allowed, endpoint, s.configDNS(nw, allowed))
		}
	}
}
