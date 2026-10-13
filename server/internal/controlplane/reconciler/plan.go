package reconciler

import (
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// plan compares one network's nodes with its live peers. Active nodes must
// be peers with their /32 among the allowed-ips; peers of inactive nodes go;
// peers that belong to no node are reported, never removed (adopt).
func plan(nw *models.Network, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) ([]Action, []string) {
	var actions []Action
	known := map[string]bool{}
	for _, n := range nodes {
		known[n.PublicKey] = true
		peer, isLive := live[n.PublicKey]
		if !n.Active(now) {
			if isLive {
				actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "remove", NodeID: n.ID, Node: n.Name, PublicKey: n.PublicKey})
			}
			continue
		}
		own := n.VirtualIP.String() + "/32"
		if !isLive {
			actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "add", NodeID: n.ID, Node: n.Name, PublicKey: n.PublicKey, AllowedIPs: own})
			continue
		}
		ips := allowedList(peer.AllowedIPs)
		if !contains(ips, own) {
			actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "update", NodeID: n.ID, Node: n.Name, PublicKey: n.PublicKey,
				AllowedIPs: strings.Join(append(ips, own), ",")}) // never shrink: keep gateway routes
		}
	}
	var unknown []string
	for k := range live {
		if !known[k] {
			unknown = append(unknown, nw.InterfaceName+":"+k)
		}
	}
	return actions, unknown
}

// allowedList splits `wg show dump` allowed-ips ("(none)" means empty).
func allowedList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && p != "(none)" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
