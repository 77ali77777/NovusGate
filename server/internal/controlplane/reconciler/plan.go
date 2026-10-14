package reconciler

import (
	"sort"
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// plan compares one network's nodes with its live peers. Active nodes must
// be peers with their /32 among the allowed-ips; peers of inactive nodes go;
// peers that belong to no node are reported, never removed (adopt).
// A public key shared by several nodes is reported as a duplicate; its peer
// is kept while any of those nodes is active (no add/remove flapping).
func plan(nw *models.Network, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) ([]Action, []string, []string) {
	byKey := map[string][]*models.Node{}
	for _, n := range nodes {
		byKey[n.PublicKey] = append(byKey[n.PublicKey], n)
	}
	var actions []Action
	var duplicates []string
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		group := byKey[k]
		if len(group) > 1 {
			names := make([]string, 0, len(group))
			for _, n := range group {
				names = append(names, n.Name)
			}
			duplicates = append(duplicates, nw.InterfaceName+": "+strings.Join(names, ", ")+" share one public key")
		}
		var active *models.Node
		for _, n := range group {
			if n.Active(now) {
				active = n
				break
			}
		}
		peer, isLive := live[k]
		if active == nil {
			if isLive {
				n := group[0]
				actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "remove", NodeID: n.ID, Node: n.Name, PublicKey: k})
			}
			continue
		}
		own := active.VirtualIP.String() + "/32"
		if !isLive {
			actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "add", NodeID: active.ID, Node: active.Name, PublicKey: k, AllowedIPs: own})
			continue
		}
		ips := allowedList(peer.AllowedIPs)
		if !contains(ips, own) {
			actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "update", NodeID: active.ID, Node: active.Name, PublicKey: k,
				AllowedIPs: strings.Join(append(ips, own), ",")}) // never shrink: keep gateway routes
		}
	}
	var unknown []string
	for k := range live {
		if _, ok := byKey[k]; !ok {
			unknown = append(unknown, nw.InterfaceName+":"+k)
		}
	}
	return actions, unknown, duplicates
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
