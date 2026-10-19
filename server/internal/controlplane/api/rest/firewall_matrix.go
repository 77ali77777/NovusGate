package rest

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
)

// handleFirewallPolicyMatrix answers GET /api/v1/firewall/policy-matrix: what
// traffic between every pair of VPN networks gets under the current VPN
// rules and firewall mode (any mode).
func (s *Server) handleFirewallPolicyMatrix(w http.ResponseWriter, r *http.Request) {
	m, warnings, err := firewall.PolicyMatrix(r.Context(), s.store, s.engineEnforces())
	if err != nil {
		engineError(w, err)
		return
	}
	logWarnings(warnings)
	jsonResponse(w, http.StatusOK, m)
}

// handleAccessCheck answers GET /api/v1/firewall/access-check?from_type=&from_id=&to_type=&to_id=:
// whether one network, device or group can reach another, both ways, under
// the current VPN rules (VLAN plan M3).
func (s *Server) handleAccessCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var ends [2]firewall.Endpoint
	for i, side := range []string{"from", "to"} {
		e := firewall.Endpoint{Type: q.Get(side + "_type"), ID: q.Get(side + "_id")}
		switch e.Type {
		case "network", "node", "group":
		default:
			errorResponse(w, http.StatusBadRequest, side+"_type must be network, node or group")
			return
		}
		if _, err := uuid.Parse(e.ID); err != nil {
			errorResponse(w, http.StatusBadRequest, side+"_id must be a UUID")
			return
		}
		ends[i] = e
	}
	res, warnings, err := firewall.AccessCheck(r.Context(), s.store, ends[0], ends[1])
	if errors.Is(err, firewall.ErrEndpoint) {
		errorResponse(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		engineError(w, err)
		return
	}
	logWarnings(warnings)
	jsonResponse(w, http.StatusOK, res)
}
