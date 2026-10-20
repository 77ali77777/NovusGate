package rest

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/novusgate/novusgate/internal/controlplane/dnsfwd"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Server-side routing, P3 (2026-10-19): a config that hands out DNS names
// the hub's address in the device's network. The hub forwards to the
// network's DNS servers (dnsfwd), so changing them changes no config.

// dnsListenAddr is where the hub answers DNS for a network whose hub
// address is hub (replaced in tests, which cannot bind port 53).
var dnsListenAddr = func(hub string) string { return net.JoinHostPort(hub, "53") }

// EnableDNS lets the server answer DNS on the hub addresses (main does;
// tests that do not leave configs naming the DNS servers directly).
func (s *Server) EnableDNS(f *dnsfwd.Forwarder) { s.dns = f }

// hubIP is a network's hub address without the prefix length.
func hubIP(cidr string) (string, error) {
	hub, err := hubAddress(cidr)
	if err != nil {
		return "", err
	}
	ip, _, _ := strings.Cut(hub, "/")
	return ip, nil
}

// dnsUpstreams are the servers a network's DNS queries go to: its client
// DNS, else the full-tunnel default.
func dnsUpstreams(n *models.Network) []string {
	var out []string
	for _, ip := range strings.Split(n.ClientDNS, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, net.JoinHostPort(ip, "53"))
		}
	}
	if len(out) == 0 {
		out = []string{net.JoinHostPort(fullTunnelDNS, "53")}
	}
	return out
}

// SyncDNS listens on every network's hub address with its upstreams. An
// address that cannot be bound yet (interface down) is retried on the next
// run (the interface check runs it every 30 s); its devices' configs name
// the DNS servers directly until then.
func (s *Server) SyncDNS(ctx context.Context) {
	if s.dns == nil {
		return
	}
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		slog.Warn("dns: networks not read", "error", err)
		return
	}
	want := map[string][]string{}
	names := map[string]string{}
	for _, n := range networks {
		if n.InterfaceName == "" {
			continue
		}
		hub, err := hubIP(n.CIDR)
		if err != nil {
			continue
		}
		addr := dnsListenAddr(hub)
		want[addr] = dnsUpstreams(n)
		names[addr] = n.Name
	}
	errs := s.dns.Sync(want)
	for addr := range want {
		msg := ""
		if err := errs[addr]; err != nil {
			msg = err.Error()
		}
		// Log a change only: the check runs every 30 s.
		if prev, _ := s.dnsErrs.Swap(addr, msg); prev != nil && prev.(string) == msg || prev == nil && msg == "" {
			continue
		}
		if msg != "" {
			slog.Warn("dns: hub address not served yet; configs name the DNS servers directly", "network", names[addr], "address", addr, "error", msg)
		} else {
			slog.Info("dns: hub answers DNS", "network", names[addr], "address", addr)
		}
	}
}

// configDNS is the DNS line of a config of network n routing allowed: the
// network's DNS servers (full tunnel: the default), named by the hub's
// address when the hub serves DNS there; "" for a split tunnel without DNS
// servers.
func (s *Server) configDNS(n *models.Network, allowed string) string {
	if n == nil {
		return ""
	}
	dns := n.ClientDNS
	if dns == "" && allowed == "0.0.0.0/0" {
		dns = fullTunnelDNS
	}
	if dns == "" || s.dns == nil {
		return dns
	}
	if hub, err := hubIP(n.CIDR); err == nil && s.dns.Listening(dnsListenAddr(hub)) {
		return hub
	}
	return dns
}
