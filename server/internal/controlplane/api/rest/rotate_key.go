package rest

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// handleRotateNodeKey answers POST /api/v1/nodes/{id}/rotate-key (VLAN plan
// M4): the device gets a new key pair and the old config stops working at
// once. Used for a config the server does not hold (the installer's admin
// config, an imported peer) or one that leaked. The new config is then
// downloaded as usual; until then the device shows it as outdated.
func (s *Server) handleRotateNodeKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	// One rotation of a device at a time: two at once (one reading the node
	// before the other wrote) could leave its address on a key whose private
	// half was not kept.
	defer s.lockInterface("rotate:" + id)()
	ctx := r.Context()
	node, err := s.store.GetNode(ctx, id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get node")
		return
	}
	if node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	// The caller's own device would lose its peer before the new config is
	// downloaded (the panel answers only over the admin VPN).
	if node.VirtualIP != nil && node.VirtualIP.String() == clientIP(r) {
		errorWithCode(w, http.StatusConflict, "rotate_own_device",
			"this request comes through this device: rotate its key from another device")
		return
	}
	priv, pub, err := wireguard.GenerateKeys()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to generate keys")
		return
	}
	pc := nodePeerControl(s, node.NetworkID)
	// The old peer goes first: if it cannot be removed, nothing changes and
	// the old config is not left working beside a "rotated" key.
	if pc != nil && node.PublicKey != "" {
		if err := pc.RemovePeer(node.PublicKey); err != nil {
			slog.Error("rotate key: old peer not removed", "node", node.Name, "error", err)
			errorResponse(w, http.StatusInternalServerError, "failed to remove the old peer")
			return
		}
	}
	own := ""
	if node.VirtualIP != nil {
		own = node.VirtualIP.String() + "/32"
	}
	if err := s.store.SetNodeKeys(ctx, id, pub, priv); err != nil {
		if pc != nil && node.PublicKey != "" && own != "" && node.Active(time.Now()) {
			if rerr := ensurePeer(pc, node.PublicKey, own); rerr != nil {
				slog.Error("rotate key: old peer not restored", "node", node.Name, "error", rerr)
			}
		}
		if errors.Is(err, sql.ErrNoRows) {
			errorResponse(w, http.StatusNotFound, "node not found")
			return
		}
		errorResponse(w, http.StatusInternalServerError, "failed to store the new key")
		return
	}
	node.PublicKey, node.ConfigRoutes, node.HasConfig = pub, "", true
	// An inactive device (expired, disabled) gets its peer when it is
	// reactivated; the reconciler adds a peer this misses.
	if pc != nil && own != "" && node.Active(time.Now()) {
		if err := ensurePeer(pc, pub, own); err != nil {
			slog.Error("rotate key: new peer not added", "node", node.Name, "error", err)
			errorWithCode(w, http.StatusInternalServerError, "rotate_peer_not_added",
				"the key was changed but the device's peer could not be added; use Restore connection")
			return
		}
	}
	slog.Info("device key rotated", "node", node.Name)
	s.markOutdated(ctx, node)
	s.triggerReconcile()
	jsonResponse(w, http.StatusOK, node)
}
