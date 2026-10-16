package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// NetworkTunnelRequest sets what a network's nodes route through the hub.
type NetworkTunnelRequest struct {
	TunnelMode string `json:"tunnel_mode"` // "split" or "full"
}

// NodeTunnelRequest sets one node's tunnel mode.
type NodeTunnelRequest struct {
	TunnelOverride string `json:"tunnel_override"` // "split", "full", or "" to follow the network
}

// TunnelChangeItem describes a tunnel change. AffectedNodes is how many nodes
// change between split and full: each needs its config downloaded again,
// since WireGuard routes come from the config file.
type TunnelChangeItem struct {
	NetworkID      string `json:"network_id,omitempty"`
	NodeID         string `json:"node_id,omitempty"`
	TunnelMode     string `json:"tunnel_mode,omitempty"`
	TunnelOverride string `json:"tunnel_override"`
	AffectedNodes  int    `json:"affected_nodes"`
}

func (s *Server) registerTunnelRoutes(api *mux.Router) {
	api.HandleFunc("/networks/{id}/tunnel", s.handleSetNetworkTunnel).Methods("PUT")
	api.HandleFunc("/nodes/{id}/tunnel", s.handleSetNodeTunnel).Methods("PUT")
}

// effectiveMode is a node's tunnel mode: its override, or else its network's.
func effectiveMode(n store.TunnelNode) string {
	if n.Override != "" {
		return n.Override
	}
	return n.NetworkMode
}

// exitSet returns the nodes that use the hub as internet exit, sorted.
func exitSet(nodes []store.TunnelNode) []string {
	out := []string{}
	for _, n := range nodes {
		if effectiveMode(n) == models.TunnelFull {
			out = append(out, n.ID)
		}
	}
	sort.Strings(out)
	return out
}

// tunnelChange applies change to the stored tunnel settings. In nftables
// mode it goes through the engine like every firewall change (the exit set
// is recomputed with change applied; Commit stores it once it is live). In
// iptables mode only configs change, because each network's wg-quick PostUp
// already masquerades its traffic; the admin VPN (wg0), which the installer
// makes without that PostUp, cannot go full there.
func (s *Server) tunnelChange(w http.ResponseWriter, r *http.Request, item TunnelChangeItem, needsNft bool,
	change func(nodes []store.TunnelNode), commit func(ctx context.Context) error) {
	nodes, err := s.store.ListTunnelNodes(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read tunnel settings")
		return
	}
	before := make([]string, len(nodes))
	for i, n := range nodes {
		before[i] = effectiveMode(n)
	}
	change(nodes)
	for i, n := range nodes {
		if effectiveMode(n) != before[i] {
			item.AffectedNodes++
		}
	}

	// Shadow mode only checks rulesets; iptables enforces, like iptables mode.
	if !s.engineEnforces() {
		if needsNft {
			errorWithCode(w, http.StatusConflict, "full_tunnel_needs_nft",
				"full tunnel on the admin VPN (wg0) needs the nftables firewall engine")
			return
		}
		if err := commit(r.Context()); err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to store the tunnel mode")
			return
		}
		jsonResponse(w, http.StatusOK, V2ChangeResponse{Item: item, Warnings: []string{}})
		return
	}
	ctx := r.Context()
	s.proposeV2(w, r, item, firewall.Change{
		// Under the engine lock, from the stored nodes as they are now (a node
		// created or deleted since the request began is counted right).
		Mutate: func(st *firewall.State) error {
			now, err := s.store.ListTunnelNodes(ctx)
			if err != nil {
				return fmt.Errorf("read tunnel settings: %w", err)
			}
			change(now)
			st.EgressNodeIDs = exitSet(now)
			return nil
		},
		Commit: commit,
	})
}

func (s *Server) handleSetNetworkTunnel(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req NetworkTunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if !models.ValidTunnelMode(req.TunnelMode) {
		errorWithCode(w, http.StatusBadRequest, "invalid_tunnel_mode", `tunnel_mode must be "split" or "full"`)
		return
	}
	network, err := s.store.GetNetwork(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read the network")
		return
	}
	if network == nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	item := TunnelChangeItem{NetworkID: id, TunnelMode: req.TunnelMode}
	if network.TunnelMode == req.TunnelMode {
		jsonResponse(w, http.StatusOK, V2ChangeResponse{Item: item, Warnings: []string{}}) // nothing to change
		return
	}
	needsNft := network.InterfaceName == nft.AdminInterface && req.TunnelMode == models.TunnelFull
	s.tunnelChange(w, r, item, needsNft,
		func(nodes []store.TunnelNode) {
			for i := range nodes {
				if nodes[i].NetworkID == id {
					nodes[i].NetworkMode = req.TunnelMode
				}
			}
		},
		func(ctx context.Context) error {
			found, err := s.store.SetNetworkTunnelMode(ctx, id, req.TunnelMode)
			if err == nil && !found {
				err = fmt.Errorf("network %s no longer exists", id)
			}
			return err
		})
}

func (s *Server) handleSetNodeTunnel(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req NodeTunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if req.TunnelOverride != "" && !models.ValidTunnelMode(req.TunnelOverride) {
		errorWithCode(w, http.StatusBadRequest, "invalid_tunnel_mode", `tunnel_override must be "split", "full" or ""`)
		return
	}
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read the node")
		return
	}
	if node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	item := TunnelChangeItem{NodeID: id, TunnelOverride: req.TunnelOverride}
	if node.TunnelOverride == req.TunnelOverride {
		jsonResponse(w, http.StatusOK, V2ChangeResponse{Item: item, Warnings: []string{}}) // nothing to change
		return
	}
	network, err := s.store.GetNetwork(r.Context(), node.NetworkID)
	if err != nil || network == nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read the node's network")
		return
	}
	effective := req.TunnelOverride
	if effective == "" {
		effective = network.TunnelMode
	}
	needsNft := network.InterfaceName == nft.AdminInterface && effective == models.TunnelFull
	s.tunnelChange(w, r, item, needsNft,
		func(nodes []store.TunnelNode) {
			for i := range nodes {
				if nodes[i].ID == id {
					nodes[i].Override = req.TunnelOverride
				}
			}
		},
		func(ctx context.Context) error { return s.store.SetNodeTunnelOverride(ctx, id, req.TunnelOverride) })
}
