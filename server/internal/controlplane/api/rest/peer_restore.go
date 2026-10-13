package rest

import (
	"fmt"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// peerAdder is the subset of wireguard.Manager needed to restore peers.
type peerAdder interface {
	AddPeer(publicKey, allowedIPs string) error
}

// restorePeers adds every active node that is missing from the live interface.
// It returns the number of peers added and one message per failed node.
func restorePeers(mgr peerAdder, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) (int, []string) {
	added := 0
	errs := []string{}
	for _, node := range nodes {
		if !node.Active(now) {
			continue
		}
		if _, ok := live[node.PublicKey]; ok {
			continue
		}
		if err := mgr.AddPeer(node.PublicKey, node.VirtualIP.String()+"/32"); err != nil {
			errs = append(errs, fmt.Sprintf("failed to add %s: %v", node.Name, err))
			continue
		}
		added++
	}
	return added, errs
}
