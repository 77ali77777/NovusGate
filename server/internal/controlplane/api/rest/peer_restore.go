package rest

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// peerAdder is the subset of wireguard.Manager needed to restore peers.
type peerAdder interface {
	AddPeer(publicKey, allowedIPs string) error
}

// peerControl is what node edits need from one WireGuard interface;
// *wireguard.Manager satisfies it.
type peerControl interface {
	GetPeers() (map[string]wireguard.PeerStatus, error)
	AddPeer(publicKey, allowedIPs string) error
	UpdatePeerAllowedIPs(publicKey, allowedIPs string) error
	RemovePeer(publicKey string) error
}

// nodePeerControl returns the interface of a node's network, or nil when no
// manager runs for it (replaced in tests).
var nodePeerControl = func(s *Server, networkID string) peerControl {
	if mgr := s.getManager(networkID); mgr != nil {
		return mgr
	}
	return nil
}

// allowedIPList splits a peer's allowed-ips ("(none)" means empty).
func allowedIPList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && p != "(none)" {
			out = append(out, p)
		}
	}
	return out
}

// routedElsewhere names the peer other than key whose allowed-ips already
// cover own, or "" when none does; adding own to key would take it away.
func routedElsewhere(live map[string]wireguard.PeerStatus, key, own string) string {
	addr, err := netip.ParsePrefix(own)
	if err != nil {
		return ""
	}
	for k, p := range live {
		if k == key {
			continue
		}
		for _, cidr := range allowedIPList(p.AllowedIPs) {
			if pfx, err := netip.ParsePrefix(cidr); err == nil && pfx.Contains(addr.Addr()) {
				return k
			}
		}
	}
	return ""
}

// ensurePeer makes a node's peer carry own (its /32) without shrinking a
// live peer's other allowed-ips (gateway routes) and without taking own
// from another peer.
func ensurePeer(pc peerControl, key, own string) error {
	live, err := pc.GetPeers()
	if err != nil {
		return err
	}
	if other := routedElsewhere(live, key, own); other != "" {
		return fmt.Errorf("%s is already routed to another peer (%s)", own, other)
	}
	p, isLive := live[key]
	if !isLive {
		return pc.AddPeer(key, own)
	}
	ips := allowedIPList(p.AllowedIPs)
	for _, ip := range ips {
		if ip == own {
			return nil
		}
	}
	return pc.UpdatePeerAllowedIPs(key, strings.Join(append(ips, own), ","))
}

// restorePeers adds every active node that is missing from the live
// interface. It returns the peers added, the nodes skipped (already live,
// or inactive: expired or disabled) and one message per node it could not
// add. Nodes without a key or address can never be peers and are not
// counted.
func restorePeers(mgr peerAdder, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) (int, int, []string) {
	added, skipped := 0, 0
	errs := []string{}
	for _, node := range nodes {
		if node.PublicKey == "" || node.VirtualIP == nil {
			continue
		}
		if !node.Active(now) {
			skipped++
			continue
		}
		if _, ok := live[node.PublicKey]; ok {
			skipped++
			continue
		}
		own := node.VirtualIP.String() + "/32"
		if other := routedElsewhere(live, node.PublicKey, own); other != "" {
			errs = append(errs, fmt.Sprintf("not adding %s: %s is already routed to another peer", node.Name, own))
			continue
		}
		if err := mgr.AddPeer(node.PublicKey, own); err != nil {
			errs = append(errs, fmt.Sprintf("failed to add %s: %v", node.Name, err))
			continue
		}
		slog.Info("restored peer", "node", node.Name, "allowed_ips", own)
		added++
	}
	return added, skipped, errs
}
