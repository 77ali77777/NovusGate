package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// LimitProfileRequest creates or replaces a limit profile (P9b). Speeds are
// kbit/s; null means unlimited.
type LimitProfileRequest struct {
	Name           string                  `json:"name"`
	DownKbps       *int                    `json:"down_kbps"`
	UpKbps         *int                    `json:"up_kbps"`
	MaxConnections *int                    `json:"max_connections"`
	Schedule       []models.ScheduleWindow `json:"schedule"`
	Timezone       string                  `json:"timezone"`
}

// LimitBindingsRequest makes these the nodes and groups bound to a profile.
type LimitBindingsRequest struct {
	NodeIDs  []string `json:"node_ids"`
	GroupIDs []string `json:"group_ids"`
}

// LimitProfilesResponse lists the profiles and the profile in force for
// every limited node. Enforcing is false unless the nft engine runs: the
// iptables firewall does not apply limits.
type LimitProfilesResponse struct {
	Profiles   []models.LimitProfile `json:"profiles"`
	NodeLimits []models.NodeLimit    `json:"node_limits"`
	Enforcing  bool                  `json:"enforcing"`
}

func (s *Server) registerLimitRoutes(api *mux.Router) {
	api.HandleFunc("/limits", s.handleListLimits).Methods("GET")
	api.HandleFunc("/limits", s.handleCreateLimit).Methods("POST")
	api.HandleFunc("/limits/{id}", s.handleUpdateLimit).Methods("PUT")
	api.HandleFunc("/limits/{id}", s.handleDeleteLimit).Methods("DELETE")
	api.HandleFunc("/limits/{id}/bindings", s.handleSetLimitBindings).Methods("PUT")
}

func limitStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLimitNameTaken):
		errorWithCode(w, http.StatusConflict, "limit_name_taken", err.Error())
	case errors.Is(err, store.ErrLimitInUse):
		errorWithCode(w, http.StatusConflict, "limit_in_use", err.Error())
	case errors.Is(err, sql.ErrNoRows):
		errorResponse(w, http.StatusNotFound, "limit profile not found")
	default:
		slog.Error("limit profile change failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to change the limit profile")
	}
}

// limitID returns the {id} path value when it is a UUID; otherwise it
// answers 404 and returns "".
func limitID(w http.ResponseWriter, r *http.Request) string {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		errorResponse(w, http.StatusNotFound, "limit profile not found")
		return ""
	}
	return id
}

func decodeLimitRequest(w http.ResponseWriter, r *http.Request) (models.LimitProfile, bool) {
	var req LimitProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return models.LimitProfile{}, false
	}
	p := models.LimitProfile{Name: strings.TrimSpace(req.Name), DownKbps: req.DownKbps, UpKbps: req.UpKbps,
		MaxConnections: req.MaxConnections, Schedule: req.Schedule, Timezone: req.Timezone}
	if p.Schedule == nil {
		p.Schedule = []models.ScheduleWindow{}
	}
	if err := firewall.ValidateLimitProfile(p); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return p, false
	}
	return p, true
}

// applyLimits re-applies the firewall after a limit change; only the nft
// engine enforces limits.
func (s *Server) applyLimits(ctx context.Context) {
	if !s.engineEnforces() {
		return
	}
	if _, err := s.firewall.ReconcileOrRetry(ctx); err != nil {
		slog.Warn(fmt.Sprintf("firewall: applying limit profiles failed (will retry): %v", err))
	}
}

// limitProfile reads one profile with its bindings.
func (s *Server) limitProfile(ctx context.Context, id string) (*models.LimitProfile, error) {
	profiles, err := s.store.ListLimitProfiles(ctx)
	if err != nil {
		return nil, err
	}
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *Server) handleListLimits(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.store.ListLimitProfiles(r.Context())
	if err != nil {
		limitStoreError(w, err)
		return
	}
	nodeLimits, err := s.store.ListNodeLimits(r.Context())
	if err != nil {
		limitStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, LimitProfilesResponse{Profiles: profiles, NodeLimits: nodeLimits, Enforcing: s.engineEnforces()})
}

func (s *Server) handleCreateLimit(w http.ResponseWriter, r *http.Request) {
	p, ok := decodeLimitRequest(w, r)
	if !ok {
		return
	}
	if err := s.store.CreateLimitProfile(r.Context(), &p); err != nil {
		limitStoreError(w, err)
		return
	}
	p.NodeIDs, p.GroupIDs = []string{}, []string{}
	jsonResponse(w, http.StatusCreated, p)
}

// handleUpdateLimit replaces a profile's limits; bound nodes get them at once.
func (s *Server) handleUpdateLimit(w http.ResponseWriter, r *http.Request) {
	id := limitID(w, r)
	if id == "" {
		return
	}
	p, ok := decodeLimitRequest(w, r)
	if !ok {
		return
	}
	p.ID = id
	if err := s.store.UpdateLimitProfile(r.Context(), &p); err != nil {
		limitStoreError(w, err)
		return
	}
	s.applyLimits(r.Context())
	updated, err := s.limitProfile(r.Context(), id)
	if err != nil {
		limitStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteLimit(w http.ResponseWriter, r *http.Request) {
	id := limitID(w, r)
	if id == "" {
		return
	}
	if err := s.store.DeleteLimitProfile(r.Context(), id); err != nil {
		limitStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetLimitBindings(w http.ResponseWriter, r *http.Request) {
	id := limitID(w, r)
	if id == "" {
		return
	}
	var req LimitBindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if _, err := s.limitProfile(r.Context(), id); err != nil {
		limitStoreError(w, err)
		return
	}
	for _, nodeID := range req.NodeIDs {
		if _, err := uuid.Parse(nodeID); err != nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unknown node %q", nodeID))
			return
		}
		if n, err := s.store.GetNode(r.Context(), nodeID); err != nil || n == nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unknown node %q", nodeID))
			return
		}
	}
	for _, groupID := range req.GroupIDs {
		if _, err := uuid.Parse(groupID); err != nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unknown group %q", groupID))
			return
		}
		if g, err := s.store.GetNodeGroup(r.Context(), groupID); err != nil || g == nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unknown group %q", groupID))
			return
		}
	}
	if err := s.store.SetLimitProfileBindings(r.Context(), id, req.NodeIDs, req.GroupIDs); err != nil {
		limitStoreError(w, err)
		return
	}
	s.applyLimits(r.Context())
	updated, err := s.limitProfile(r.Context(), id)
	if err != nil {
		limitStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, updated)
}
