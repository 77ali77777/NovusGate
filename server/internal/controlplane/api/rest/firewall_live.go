package rest

import (
	"log/slog"
	"net/http"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/conntrack"
	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// conntrackRoot is /proc; tests point it at a fake tree.
var conntrackRoot = "/proc"

// handleFirewallV2Live answers GET /api/v1/firewall/v2/live. It works in
// every firewall mode: without the nft engine only conntrack is filled.
func (s *Server) handleFirewallV2Live(w http.ResponseWriter, r *http.Request) {
	resp := V2LiveResponse{
		Mode:      firewall.ModeIptables,
		Counters:  []nft.RuleCounter{},
		Dropped:   []nft.DroppedSource{},
		Conntrack: conntrack.Read(conntrackRoot),
	}
	if s.firewall != nil {
		resp.Mode = s.firewall.Mode
		live, err := s.firewall.Live()
		if err != nil {
			// nft's message names no secrets; it says why the panel shows nothing.
			slog.Warn("firewall live view failed", "error", err)
			resp.Error = err.Error()
		}
		resp.TableLoaded = live.TableLoaded
		if live.Counters != nil {
			resp.Counters = live.Counters
		}
		if live.Dropped != nil {
			resp.Dropped = live.Dropped
		}
	}
	jsonResponse(w, http.StatusOK, resp)
}
