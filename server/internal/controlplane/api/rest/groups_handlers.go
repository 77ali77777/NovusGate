package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// NodeGroupRequest creates or renames a node group (P9a).
type NodeGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// NodeGroupMembersRequest replaces a group's members.
type NodeGroupMembersRequest struct {
	NodeIDs []string `json:"node_ids"`
}

// NodeGroupsResponse lists the groups by name.
type NodeGroupsResponse struct {
	Groups []*models.NodeGroup `json:"groups"`
}

func (s *Server) registerGroupRoutes(api *mux.Router) {
	api.HandleFunc("/groups", s.handleListGroups).Methods("GET")
	api.HandleFunc("/groups", s.handleCreateGroup).Methods("POST")
	api.HandleFunc("/groups/{id}", s.handleUpdateGroup).Methods("PUT")
	api.HandleFunc("/groups/{id}", s.handleDeleteGroup).Methods("DELETE")
	api.HandleFunc("/groups/{id}/members", s.handleSetGroupMembers).Methods("PUT")
}

func decodeGroupRequest(w http.ResponseWriter, r *http.Request) (NodeGroupRequest, bool) {
	var req NodeGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return req, false
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		errorResponse(w, http.StatusBadRequest, "name is required (at most 100 characters)")
		return req, false
	}
	return req, true
}

func groupStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrGroupNameTaken):
		errorWithCode(w, http.StatusConflict, "group_name_taken", err.Error())
	case errors.Is(err, store.ErrGroupInUse):
		errorWithCode(w, http.StatusConflict, "group_in_use", err.Error())
	case errors.Is(err, sql.ErrNoRows):
		errorResponse(w, http.StatusNotFound, "group not found")
	default:
		slog.Error("node group change failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to change the group")
	}
}

// groupID returns the {id} path value when it is a UUID; otherwise it
// answers 404 and returns "".
func groupID(w http.ResponseWriter, r *http.Request) string {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		errorResponse(w, http.StatusNotFound, "group not found")
		return ""
	}
	return id
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListNodeGroups(r.Context())
	if err != nil {
		groupStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, NodeGroupsResponse{Groups: groups})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeGroupRequest(w, r)
	if !ok {
		return
	}
	g := &models.NodeGroup{Name: req.Name, Description: req.Description, Members: []models.NodeGroupMember{}}
	if err := s.store.CreateNodeGroup(r.Context(), g); err != nil {
		groupStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, g)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := groupID(w, r)
	if id == "" {
		return
	}
	req, ok := decodeGroupRequest(w, r)
	if !ok {
		return
	}
	if err := s.store.UpdateNodeGroup(r.Context(), &models.NodeGroup{ID: id, Name: req.Name, Description: req.Description}); err != nil {
		groupStoreError(w, err)
		return
	}
	g, err := s.store.GetNodeGroup(r.Context(), id)
	if err != nil {
		groupStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, g)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := groupID(w, r)
	if id == "" {
		return
	}
	if err := s.store.DeleteNodeGroup(r.Context(), id); err != nil {
		groupStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSetGroupMembers replaces the members and re-applies the VPN rules,
// since a group's addresses are part of them.
func (s *Server) handleSetGroupMembers(w http.ResponseWriter, r *http.Request) {
	id := groupID(w, r)
	if id == "" {
		return
	}
	var req NodeGroupMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if g, err := s.store.GetNodeGroup(r.Context(), id); err != nil || g == nil {
		if err == nil {
			err = sql.ErrNoRows
		}
		groupStoreError(w, err)
		return
	}
	for _, nodeID := range req.NodeIDs {
		n, err := s.store.GetNode(r.Context(), nodeID)
		if err != nil || n == nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unknown node %q", nodeID))
			return
		}
	}
	if err := s.store.SetNodeGroupMembers(r.Context(), id, req.NodeIDs); err != nil {
		groupStoreError(w, err)
		return
	}
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		slog.Error(fmt.Sprintf("Warning: failed to sync VPN firewall rules: %v", err))
	}
	g, err := s.store.GetNodeGroup(r.Context(), id)
	if err != nil {
		groupStoreError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, g)
}

// checkRuleGroups verifies that the groups a VPN rule names exist and fills
// in their names for the response.
func (s *Server) checkRuleGroups(ctx context.Context, rule *models.VPNFirewallRule) error {
	for _, end := range []struct {
		id   *string
		name *string
		side string
	}{{rule.SourceGroupID, &rule.SourceGroupName, "source"}, {rule.DestGroupID, &rule.DestGroupName, "destination"}} {
		if end.id == nil {
			continue
		}
		if _, err := uuid.Parse(*end.id); err != nil {
			return fmt.Errorf("%s group not found", end.side)
		}
		g, err := s.store.GetNodeGroup(ctx, *end.id)
		if err != nil {
			return err
		}
		if g == nil {
			return fmt.Errorf("%s group not found", end.side)
		}
		*end.name = g.Name
	}
	return nil
}

// groupNetworkCIDRs returns the CIDRs of the networks a group's members are
// in, sorted and without repeats (for the AllowedIPs routes of accept rules).
func (s *Server) groupNetworkCIDRs(ctx context.Context, groupID *string, networkCIDRs map[string]string) []string {
	if groupID == nil {
		return nil
	}
	g, err := s.store.GetNodeGroup(ctx, *groupID)
	if err != nil || g == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range g.Members {
		if cidr, ok := networkCIDRs[m.NetworkID]; ok && !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out
}
