package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
)

// V2HistoryEntry is one applied firewall change: what it added and removed,
// compared with the entry before it ("baseline" lists the starting state).
type V2HistoryEntry struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Username  string    `json:"username,omitempty"`
	Action    string    `json:"action"`
	Added     []string  `json:"added"`
	Removed   []string  `json:"removed"`
}

// V2HistoryResponse lists the newest entries first.
type V2HistoryResponse struct {
	Entries []V2HistoryEntry `json:"entries"`
}

// firewallActorMiddleware puts who and what on the request context, so the
// engine's history names the user and the endpoint of every change.
func (s *Server) firewallActorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := firewall.WithActor(r.Context(), firewall.Actor{Label: r.Method + " " + r.URL.Path, UserID: sessionUserID(r)})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) handleFirewallV2History(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	// One more than shown: the oldest shown entry needs its predecessor.
	rows, err := s.store.ListFirewallHistory(r.Context(), limit+1)
	if err != nil {
		engineError(w, err)
		return
	}
	names, err := s.nodeNames(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	lines := make([][]string, len(rows))
	for i, row := range rows {
		var st firewall.State
		if err := json.Unmarshal(row.State, &st); err != nil {
			engineError(w, fmt.Errorf("history entry %s: %w", row.ID, err))
			return
		}
		lines[i] = firewall.Describe(st, names)
	}
	resp := V2HistoryResponse{Entries: []V2HistoryEntry{}}
	for i, row := range rows {
		if i == limit {
			break
		}
		var prev []string
		if i+1 < len(rows) {
			prev = lines[i+1]
		}
		added, removed := firewall.DiffLines(prev, lines[i])
		resp.Entries = append(resp.Entries, V2HistoryEntry{ID: row.ID, CreatedAt: row.CreatedAt, Username: row.Username,
			Action: row.Action, Added: added, Removed: removed})
	}
	jsonResponse(w, http.StatusOK, resp)
}

// handleFirewallV2Restore brings back the state stored in a history entry.
// It goes through the engine like any change (confirmation and automatic
// rollback included). Expired IP rules and egress of deleted nodes are left
// out.
func (s *Server) handleFirewallV2Restore(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		engineError(w, fmt.Errorf("history entry %w", errNotFound))
		return
	}
	entry, err := s.store.GetFirewallHistory(r.Context(), id)
	if err != nil {
		engineError(w, err)
		return
	}
	if entry == nil {
		engineError(w, fmt.Errorf("history entry %w", errNotFound))
		return
	}
	var snap firewall.State
	if err := json.Unmarshal(entry.State, &snap); err != nil {
		engineError(w, fmt.Errorf("history entry %s: %w", id, err))
		return
	}
	now := time.Now()
	rules := snap.IPRules[:0]
	for _, rule := range snap.IPRules {
		if rule.ExpiresAt == nil || rule.ExpiresAt.After(now) {
			rules = append(rules, rule)
		}
	}
	snap.IPRules = rules

	actor := firewall.ActorFrom(r.Context())
	actor.Label = "restore " + entry.CreatedAt.UTC().Format("2006-01-02 15:04:05") + " UTC"
	r = r.WithContext(firewall.WithActor(r.Context(), actor))
	s.proposeV2(w, r, IDItem{ID: id}, firewall.Change{
		// Tunnel modes are network and device settings, not restored: the
		// internet exit set stays the current one.
		Mutate: func(st *firewall.State) error {
			egress := st.EgressNodeIDs
			*st = snap
			st.EgressNodeIDs = egress
			return nil
		},
		Commit: func(ctx context.Context) error {
			return s.store.ReplaceFirewallState(ctx, snap.Services, snap.IPRules, snap.Forwards)
		},
	})
}

// nodeNames maps every node ID to its name.
func (s *Server) nodeNames(ctx context.Context) (map[string]string, error) {
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, nw := range networks {
		nodes, err := s.store.ListNodes(ctx, nw.ID)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			names[n.ID] = n.Name
		}
	}
	return names, nil
}
