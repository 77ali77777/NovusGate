package rest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// errNotFound is returned by engine mutations that reference a missing record.
var errNotFound = errors.New("not found")

// errConflict is returned by engine mutations that collide with a stored record.
var errConflict = errors.New("conflict")

// clearLegacyVPNRules removes the iptables novusgate-vpn-* FORWARD rules
// (replaced in tests).
var clearLegacyVPNRules = (*Server).clearNovusGateVPNRules

// checkFirewallHost and cutoverIptables run on the host (replaced in tests).
var checkFirewallHost = func() error { return firewall.CheckHost(nft.NsenterRunner{}) }

var cutoverIptables = func() (int, error) { return firewall.CutoverIptables(nft.NsenterRunner{}) }

// adminPeers lists the admin network's WireGuard peers (replaced in tests).
var adminPeers = func() (map[string]wireguard.PeerStatus, error) {
	return wireguard.NewManager(nft.AdminInterface).GetPeers()
}

// SetFirewall attaches the nftables engine. Without it, or in iptables mode,
// the legacy iptables code paths are used everywhere. In nft mode every apply
// keeps the admin peers' WireGuard endpoints reachable, and the legacy
// iptables VPN rules and INPUT filtering are handed over only after nftables
// first applies.
func (s *Server) SetFirewall(e *firewall.Engine) {
	s.firewall = e
	if e == nil || e.Mode != firewall.ModeNft {
		return
	}
	e.Protect = adminEndpoints
	handedOver := false // guarded by the engine lock AfterApply runs under
	e.AfterApply = func() {
		if handedOver {
			return
		}
		if err := clearLegacyVPNRules(s); err != nil {
			slog.Warn(fmt.Sprintf("[Firewall] warning: could not remove legacy iptables VPN rules (will retry): %v", err))
			return
		}
		n, err := cutoverIptables()
		if err != nil {
			slog.Warn(fmt.Sprintf("[Firewall] warning: iptables INPUT hand-over failed (will retry): %v", err))
			return
		}
		slog.Info(fmt.Sprintf("[Firewall] iptables INPUT handed over to nftables (%d rules removed)", n))
		handedOver = true
	}
}

// adminEndpoints returns the public endpoints of the admin network's peers,
// read live from wg0 so they are known before its manager is registered.
func adminEndpoints() []netip.Addr {
	peers, err := adminPeers()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, p := range peers {
		if ap, err := netip.ParseAddrPort(p.Endpoint); err == nil {
			out = append(out, ap.Addr().Unmap())
		}
	}
	return out
}

// engineEnforces reports whether nftables (not iptables) enforces the host firewall.
func (s *Server) engineEnforces() bool {
	return s.firewall != nil && s.firewall.Mode == firewall.ModeNft
}

// StartFirewall prepares the engine at startup: shadow mode validates the
// ruleset; nft mode imports panel-made iptables rules once, removes the
// legacy VPN rules from iptables and applies the stored state.
func (s *Server) StartFirewall(ctx context.Context) error {
	if s.firewall == nil {
		return nil
	}
	switch s.firewall.Mode {
	case firewall.ModeShadow:
		warnings, err := s.firewall.Check(ctx)
		logWarnings(warnings)
		if err != nil {
			return fmt.Errorf("shadow check failed: %w", err)
		}
		slog.Info("[Firewall] shadow mode: nftables ruleset compiles and passes nft -c")
	case firewall.ModeNft:
		if err := checkFirewallHost(); err != nil {
			return fmt.Errorf("host not ready for FIREWALL_ENGINE=nft (iptables keeps enforcing): %w", err)
		}
		host, err := s.firewall.Detect()
		if err != nil {
			return err
		}
		n, skipped, err := firewall.ImportIptables(ctx, s.store, nft.NsenterRunner{}, host.SSHPorts, time.Now())
		if err != nil {
			return err
		}
		if n > 0 || len(skipped) > 0 {
			slog.Info(fmt.Sprintf("[Firewall] imported %d panel rules from iptables (%d installer/foreign rules not imported)", n, len(skipped)))
		}
		s.firewall.MarkReady()
		// The legacy iptables VPN rules are removed by AfterApply once this (or
		// a retried) apply succeeds, so a failure never leaves FORWARD open.
		res, err := s.firewall.ReconcileOrRetry(ctx)
		logWarnings(res.Warnings)
		if err != nil {
			return fmt.Errorf("initial apply failed (iptables keeps enforcing, retrying in the background): %w", err)
		}
		slog.Info("[Firewall] nftables engine applied the stored ruleset")
	}
	return nil
}

// reconcileFirewall re-applies the stored state after a change that affects
// the ruleset (networks, nodes, VPN rules). Errors are logged, not returned:
// the triggering request already succeeded; the engine retries in the
// background.
func (s *Server) reconcileFirewall(ctx context.Context) {
	if !s.engineEnforces() {
		return
	}
	res, err := s.firewall.ReconcileOrRetry(ctx)
	logWarnings(res.Warnings)
	if err != nil {
		slog.Warn(fmt.Sprintf("[Firewall] reconcile failed (will retry): %v", err))
	}
}

func logWarnings(warnings []error) {
	for _, w := range warnings {
		slog.Warn(fmt.Sprintf("[Firewall] warning: %v", w))
	}
}

// protectAddrs returns the addresses the request comes from, plus the public
// WireGuard endpoint of that peer when it arrives over the VPN, so a change
// can never cut off the operator making it.
func (s *Server) protectAddrs(r *http.Request) []netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	remote = remote.Unmap()
	addrs := []netip.Addr{remote}
	if ep, ok := s.wireGuardEndpointFor(remote); ok {
		addrs = append(addrs, ep)
	}
	return addrs
}

// wireGuardEndpointFor finds the public endpoint of the peer that owns addr.
func (s *Server) wireGuardEndpointFor(addr netip.Addr) (netip.Addr, bool) {
	s.managersMu.RLock()
	defer s.managersMu.RUnlock()
	var all []wireguard.PeerStatus
	for _, mgr := range s.managers {
		peers, err := mgr.GetPeers()
		if err != nil {
			continue
		}
		for _, p := range peers {
			all = append(all, p)
		}
	}
	return endpointForAddr(all, addr)
}

// endpointForAddr returns the endpoint of the peer whose AllowedIPs match
// addr most specifically, so a gateway with 0.0.0.0/0 never hides the
// operator's own peer.
func endpointForAddr(peers []wireguard.PeerStatus, addr netip.Addr) (netip.Addr, bool) {
	best, bestBits := netip.Addr{}, -1
	for _, p := range peers {
		ap, err := netip.ParseAddrPort(p.Endpoint)
		if err != nil {
			continue
		}
		for _, allowed := range strings.Split(p.AllowedIPs, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(allowed))
			if err != nil || !prefix.Contains(addr) || prefix.Bits() <= bestBits {
				continue
			}
			best, bestBits = ap.Addr().Unmap(), prefix.Bits()
		}
	}
	return best, bestBits >= 0
}

// engineError writes the HTTP status that matches an engine error.
func engineError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotFound):
		errorResponse(w, http.StatusNotFound, err.Error())
	case errors.Is(err, firewall.ErrEngineDisabled),
		errors.Is(err, firewall.ErrNotReady),
		errors.Is(err, errConflict),
		errors.Is(err, nft.ErrPendingConfirmation),
		errors.Is(err, nft.ErrRollbackArmed):
		errorResponse(w, http.StatusConflict, err.Error())
	case errors.Is(err, firewall.ErrRejected):
		errorResponse(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, nft.ErrExpired), errors.Is(err, nft.ErrNoPending):
		errorResponse(w, http.StatusGone, err.Error())
	default:
		errorResponse(w, http.StatusInternalServerError, err.Error())
	}
}

func warningStrings(warnings []error) []string {
	out := make([]string, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, w.Error())
	}
	return out
}

// canonicalPrefix turns "a.b.c.d", "a.b.c.d/n" or IPv6 forms into a masked
// CIDR string, unmapping IPv4-mapped addresses.
func canonicalPrefix(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return "", fmt.Errorf("invalid CIDR %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}
