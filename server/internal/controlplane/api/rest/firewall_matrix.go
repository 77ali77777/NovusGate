package rest

import (
	"net/http"

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
