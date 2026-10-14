package rest

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/traffic"
)

// NodeTrafficResponse is a node's traffic history: bytes per interval.
type NodeTrafficResponse struct {
	NodeID        string          `json:"node_id"`
	Range         string          `json:"range"`          // 24h, 7d or 30d
	BucketSeconds int             `json:"bucket_seconds"` // length of each point's interval
	Points        []traffic.Point `json:"points"`         // oldest first; rx/tx as the hub counts them
}

// trafficNow is the end of the history window (replaced in tests).
var trafficNow = time.Now

type trafficRange struct {
	span    time.Duration
	buckets int
}

// trafficRanges keep about 200-300 points per chart: 5 minutes for a day,
// an hour for a week, 4 hours for 30 days (the retention).
var trafficRanges = map[string]trafficRange{
	"24h": {24 * time.Hour, 288},
	"7d":  {7 * 24 * time.Hour, 168},
	"30d": {30 * 24 * time.Hour, 180},
}

// handleNodeTraffic serves GET /nodes/{id}/traffic?range=24h|7d|30d.
func (s *Server) handleNodeTraffic(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	name := r.URL.Query().Get("range")
	if name == "" {
		name = "24h"
	}
	rg, ok := trafficRanges[name]
	if !ok {
		errorWithCode(w, http.StatusBadRequest, "invalid_range", "range must be 24h, 7d or 30d")
		return
	}
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get node")
		return
	}
	if node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	to := trafficNow().UTC()
	from := to.Add(-rg.span)
	samples, err := s.store.ListTrafficSamples(r.Context(), id, from)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read traffic history")
		return
	}
	jsonResponse(w, http.StatusOK, NodeTrafficResponse{
		NodeID:        id,
		Range:         name,
		BucketSeconds: int(rg.span.Seconds()) / rg.buckets,
		Points:        traffic.Series(samples, from, to, rg.buckets),
	})
}
