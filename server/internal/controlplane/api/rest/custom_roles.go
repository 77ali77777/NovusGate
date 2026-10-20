package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Custom roles (2026-10-20). An admin defines which sections a role sees
// (view) or changes (edit) and, optionally, the networks it is limited to.
// A custom role never gets more than an operator: "edit" exists only where
// an operator can change things; server administration, users, roles,
// backups and host firewall changes stay with admins.

// roleSections are the sections, in panel order, and whether a custom
// role may get "edit" there.
var roleSections = []struct {
	Key  string
	Edit bool
}{
	{"dashboard", false},
	{"networks", true},
	{"devices", true},
	{"configs", false}, // view: download configs, QR codes, install scripts (private keys)
	{"groups", true},
	{"vpn_rules", true},
	{"limits", true},
	{"host_firewall", false},
	{"fail2ban", false},
	{"audit", false},
}

// scopedSections are what a role limited to networks may have: the others
// show or change several networks at once.
var scopedSections = map[string]bool{"networks": true, "devices": true, "configs": true}

// personalRoutes concern the caller's own account: every signed-in user.
var personalRoutes = func() map[string]bool {
	out := map[string]bool{
		"GET /api/v1/auth/me":       true,
		"GET /api/v1/auth/sessions": true, // the handler shows a non-admin only its own
		"GET /api/v1/openapi.json":  true,
	}
	for k := range anyRoleRoutes {
		out[k] = true
	}
	return out
}()

// notForCustomRoles are viewer reads a custom role does not get.
var notForCustomRoles = map[string]bool{
	"GET /api/v1/backups": true, // backups are an admin's
}

// routeSections maps every route an operator or viewer may use to its
// section (TestEverySharedRouteHasASection keeps it complete).
var routeSections = map[string]string{
	"GET /api/v1/stats/overview": "dashboard",
	"GET /api/v1/system/info":    "dashboard",

	"GET /api/v1/networks":               "networks",
	"GET /api/v1/networks/{id}":          "networks",
	"GET /api/v1/settings/vpn":           "networks",
	"POST /api/v1/networks":              "networks",
	"DELETE /api/v1/networks/{id}":       "networks",
	"PUT /api/v1/networks/{id}/dns":      "networks",
	"POST /api/v1/networks/{id}/restart": "networks",

	"GET /api/v1/networks/{networkId}/nodes":    "devices",
	"GET /api/v1/nodes/{id}":                    "devices",
	"GET /api/v1/nodes/{id}/traffic":            "devices",
	"POST /api/v1/networks/{networkId}/servers": "devices",
	"POST /api/v1/networks/{networkId}/sync":    "devices",
	"PUT /api/v1/nodes/{id}":                    "devices",
	"PATCH /api/v1/nodes/{id}":                  "devices",
	"DELETE /api/v1/nodes/{id}":                 "devices",
	"POST /api/v1/nodes/{id}/rotate-key":        "devices",
	"POST /api/v1/nodes/{id}/checkin":           "devices",

	"GET /api/v1/nodes/{id}/config":     "configs",
	"GET /api/v1/nodes/{id}/qrcode":     "configs",
	"GET /api/v1/nodes/{id}/install.sh": "configs",

	"GET /api/v1/groups":                     "groups",
	"POST /api/v1/groups":                    "groups",
	"PUT /api/v1/groups/{id}":                "groups",
	"DELETE /api/v1/groups/{id}":             "groups",
	"PUT /api/v1/groups/{id}/members":        "groups",
	"GET /api/v1/firewall/vpn/rules":         "vpn_rules",
	"POST /api/v1/firewall/vpn/rules":        "vpn_rules",
	"PUT /api/v1/firewall/vpn/rules/{id}":    "vpn_rules",
	"DELETE /api/v1/firewall/vpn/rules/{id}": "vpn_rules",
	"POST /api/v1/firewall/vpn/apply":        "vpn_rules",
	"GET /api/v1/firewall/policy-matrix":     "vpn_rules",
	"GET /api/v1/firewall/access-check":      "vpn_rules",

	"GET /api/v1/limits":                  "limits",
	"POST /api/v1/limits":                 "limits",
	"PUT /api/v1/limits/{id}":             "limits",
	"DELETE /api/v1/limits/{id}":          "limits",
	"PUT /api/v1/limits/{id}/bindings":    "limits",
	"POST /api/v1/nodes/{id}/quota/reset": "limits",

	"GET /api/v1/firewall/host/rules": "host_firewall",
	"GET /api/v1/firewall/v2/history": "host_firewall",
	"GET /api/v1/firewall/v2/live":    "host_firewall",
	"GET /api/v1/firewall/v2/preview": "host_firewall",
	"GET /api/v1/firewall/v2/state":   "host_firewall",

	"GET /api/v1/system/fail2ban/ban-history":    "fail2ban",
	"GET /api/v1/system/fail2ban/jail/settings":  "fail2ban",
	"GET /api/v1/system/fail2ban/logs":           "fail2ban",
	"GET /api/v1/system/fail2ban/permanent-bans": "fail2ban",
	"GET /api/v1/system/fail2ban/ping":           "fail2ban",
	"GET /api/v1/system/fail2ban/status":         "fail2ban",
	"GET /api/v1/system/fail2ban/whitelist":      "fail2ban",

	"GET /api/v1/audit": "audit",
}

var levelRank = map[string]int{"none": 0, "view": 1, "edit": 2}

// builtInPermissions are what the built-in roles amount to, for the panel.
func builtInPermissions(role string) map[string]string {
	out := map[string]string{}
	for _, s := range roleSections {
		switch role {
		case "admin":
			out[s.Key] = "edit"
			if s.Key == "dashboard" || s.Key == "audit" || s.Key == "configs" {
				out[s.Key] = "view"
			}
		case "operator":
			out[s.Key] = "view"
			if s.Edit {
				out[s.Key] = "edit"
			}
		default: // viewer
			out[s.Key] = "view"
			if s.Key == "configs" {
				out[s.Key] = "none"
			}
		}
	}
	return out
}

// access is what the signed-in user of a request may do (custom roles).
type access struct {
	role     *models.Role
	perms    map[string]string
	networks map[string]bool // nil: every network
	own      bool            // scope own: it may create networks of its own
}

type accessKey struct{}

// scopeMode is a role's scope: all, listed (network_ids) or own (the
// networks its user creates). Roles stored before scope modes say it by
// network_ids.
func scopeMode(r *models.Role) string {
	switch r.ScopeMode {
	case "all", "listed", "own":
		return r.ScopeMode
	}
	if len(r.NetworkIDs) > 0 {
		return "listed"
	}
	return "all"
}

// effectivePermissions: every section, a role limited to networks (listed
// or own) only the sections that stay inside one network.
func effectivePermissions(r *models.Role) map[string]string {
	limited := scopeMode(r) != "all"
	out := map[string]string{}
	for _, s := range roleSections {
		lvl := r.Permissions[s.Key]
		if levelRank[lvl] == 0 || (limited && !scopedSections[s.Key]) {
			lvl = "none"
		}
		out[s.Key] = lvl
	}
	return out
}

// newAccess builds a role's access; owned are the networks its user owns
// (used by scope "own").
func newAccess(r *models.Role, owned []string) *access {
	a := &access{role: r, perms: effectivePermissions(r)}
	switch scopeMode(r) {
	case "listed":
		a.networks = map[string]bool{}
		for _, id := range r.NetworkIDs {
			a.networks[id] = true
		}
	case "own":
		a.own = true
		a.networks = map[string]bool{} // empty: no network until it makes one
		for _, id := range owned {
			a.networks[id] = true
		}
	}
	return a
}

func accessFrom(r *http.Request) *access {
	a, _ := r.Context().Value(accessKey{}).(*access)
	return a
}

// seesNetwork: the request may see network id (always without a custom
// role limited to networks).
func seesNetwork(r *http.Request, id string) bool {
	a := accessFrom(r)
	return a == nil || a.networks == nil || a.networks[id]
}

// customAllows decides a custom role's request; the reason is for the 403.
func (s *Server) customAllows(r *http.Request, a *access, method, route string) (bool, string) {
	key := method + " " + route
	if method == http.MethodHead {
		key = "GET " + route
	}
	if personalRoutes[key] {
		return true, ""
	}
	sec := routeSections[key]
	if sec == "" || notForCustomRoles[key] {
		return false, "only an admin can do this"
	}
	need := "edit"
	if method == http.MethodGet || method == http.MethodHead {
		need = "view"
	}
	if levelRank[a.perms[sec]] < levelRank[need] {
		return false, "your role (" + a.role.Name + ") cannot " + need + " " + sec
	}
	if a.networks == nil {
		return true, ""
	}
	// Limited to listed networks: nothing that makes or removes a network.
	// Own networks: it makes its own (up to the limit, in the handler) and
	// removes only those (the scope check below).
	if key == "POST /api/v1/networks" {
		if a.own {
			return true, ""
		}
		return false, "your role (" + a.role.Name + ") is limited to networks: it cannot create networks"
	}
	if key == "DELETE /api/v1/networks/{id}" && !a.own {
		return false, "your role (" + a.role.Name + ") is limited to networks: it cannot delete networks"
	}
	vars := mux.Vars(r)
	netID := vars["networkId"]
	if strings.HasPrefix(route, "/api/v1/networks/{id}") {
		netID = vars["id"]
	}
	if strings.HasPrefix(route, "/api/v1/nodes/{id}") {
		node, err := s.store.GetNode(r.Context(), vars["id"])
		if err != nil {
			// Fail closed: a device that cannot be looked up is not known
			// to be inside the role's networks.
			return false, "your role (" + a.role.Name + ") is limited to networks: this device could not be checked"
		}
		if node == nil {
			return true, "" // no such device: the handler answers 404
		}
		netID = node.NetworkID
	}
	if netID != "" && !a.networks[netID] {
		return false, "your role (" + a.role.Name + ") is limited to other networks"
	}
	return true, ""
}

// loadAccess reads the custom role of a user (nil: not a custom role) and,
// for scope "own", the networks the user owns.
func (s *Server) loadAccess(ctx context.Context, user *models.User) (*access, error) {
	if user.Role != "custom" || user.RoleID == nil {
		return nil, nil
	}
	r, err := s.store.GetRole(ctx, *user.RoleID)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("role not found")
	}
	var owned []string
	if scopeMode(r) == "own" {
		if owned, err = s.store.NetworksOwnedBy(ctx, user.ID); err != nil {
			return nil, err
		}
	}
	return newAccess(r, owned), nil
}

// RoleRequest creates or changes a custom role. scope_mode: all, listed
// (network_ids) or own (each user creates up to max_networks of its own);
// left out, it follows network_ids.
type RoleRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Permissions map[string]string `json:"permissions"`
	NetworkIDs  []string          `json:"network_ids"`
	ScopeMode   string            `json:"scope_mode,omitempty"`
	MaxNetworks int               `json:"max_networks,omitempty"`
}

// RolesResponse lists the custom roles and the sections a role is made of.
type RolesResponse struct {
	Roles    []*models.Role `json:"roles"`
	Sections []RoleSection  `json:"sections"`
}

// RoleSection is one section and whether a custom role may change it.
type RoleSection struct {
	Key         string `json:"key"`
	Editable    bool   `json:"editable"`
	InsideScope bool   `json:"inside_scope"` // kept by a role limited to networks
}

// validRoleRequest checks a role; had are the networks the role has now,
// which may stay even when deleted since (fail closed: dropping them could
// leave the list empty, and empty means every network).
func (s *Server) validRoleRequest(ctx context.Context, req *RoleRequest, had []string) (*models.Role, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || utf8.RuneCountInString(name) > 100 {
		return nil, errors.New("name must be 1 to 100 characters")
	}
	if utf8.RuneCountInString(req.Description) > 500 {
		return nil, errors.New("description must be at most 500 characters")
	}
	perms := map[string]string{}
	editable := map[string]bool{}
	for _, s := range roleSections {
		editable[s.Key] = s.Edit
	}
	for k, v := range req.Permissions {
		e, ok := editable[k]
		if !ok {
			return nil, errors.New("unknown section " + k)
		}
		if _, ok := levelRank[v]; !ok {
			return nil, errors.New(k + ": level must be none, view or edit")
		}
		if v == "edit" && !e {
			return nil, errors.New(k + " can only be viewed by a custom role")
		}
		perms[k] = v
	}
	ids := []string{}
	if len(req.NetworkIDs) > 0 {
		networks, err := s.store.ListNetworks(ctx)
		if err != nil {
			return nil, err
		}
		known := map[string]bool{}
		for _, n := range networks {
			known[n.ID] = true
		}
		for _, id := range had {
			known[id] = true
		}
		seen := map[string]bool{}
		for _, id := range req.NetworkIDs {
			u, err := uuid.Parse(id)
			if err != nil || !known[u.String()] {
				return nil, errors.New("unknown network " + id)
			}
			if !seen[u.String()] {
				seen[u.String()] = true
				ids = append(ids, u.String())
			}
		}
	}
	mode := req.ScopeMode
	if mode == "" { // left out: follows network_ids, as before scope modes
		mode = "all"
		if len(ids) > 0 {
			mode = "listed"
		}
	}
	switch mode {
	case "all":
		if len(ids) > 0 {
			return nil, errors.New("scope all takes no network_ids")
		}
	case "listed":
		if len(ids) == 0 {
			return nil, errors.New("scope listed needs network_ids")
		}
	case "own":
		if len(ids) > 0 {
			return nil, errors.New("scope own takes no network_ids: its user's own networks are the scope")
		}
		if perms["networks"] != "edit" {
			return nil, errors.New("scope own needs networks: edit (its user creates the networks)")
		}
	default:
		return nil, errors.New("scope_mode must be all, listed or own")
	}
	max := 0
	if mode == "own" {
		if req.MaxNetworks < 1 || req.MaxNetworks > 1000 {
			return nil, errors.New("max_networks must be 1 to 1000")
		}
		max = req.MaxNetworks
	}
	return &models.Role{Name: name, Description: strings.TrimSpace(req.Description), Permissions: perms, NetworkIDs: ids,
		ScopeMode: mode, MaxNetworks: max}, nil
}

func (s *Server) registerCustomRoleRoutes(api *mux.Router) {
	api.HandleFunc("/roles", s.handleListRoles).Methods("GET")
	api.HandleFunc("/roles", s.handleCreateRole).Methods("POST")
	api.HandleFunc("/roles/{id}", s.handleUpdateRole).Methods("PUT")
	api.HandleFunc("/roles/{id}", s.handleDeleteRole).Methods("DELETE")
}

func roleSectionList() []RoleSection {
	out := make([]RoleSection, 0, len(roleSections))
	for _, s := range roleSections {
		out = append(out, RoleSection{Key: s.Key, Editable: s.Edit, InsideScope: scopedSections[s.Key]})
	}
	return out
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list roles")
		return
	}
	jsonResponse(w, http.StatusOK, RolesResponse{Roles: roles, Sections: roleSectionList()})
}

func roleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrRoleNameTaken):
		errorWithCode(w, http.StatusConflict, "role_name_taken", err.Error())
	case errors.Is(err, store.ErrRoleInUse):
		errorWithCode(w, http.StatusConflict, "role_in_use", err.Error())
	case errors.Is(err, sql.ErrNoRows):
		errorResponse(w, http.StatusNotFound, "role not found")
	default:
		slog.Error("role change failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to change the role")
	}
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	role, err := s.validRoleRequest(r.Context(), &req, nil)
	if err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_role", err.Error())
		return
	}
	if err := s.store.CreateRole(r.Context(), role); err != nil {
		roleError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, role)
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	current, err := s.store.GetRole(r.Context(), mux.Vars(r)["id"])
	if err != nil {
		roleError(w, err)
		return
	}
	if current == nil {
		roleError(w, sql.ErrNoRows)
		return
	}
	role, err := s.validRoleRequest(r.Context(), &req, current.NetworkIDs)
	if err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_role", err.Error())
		return
	}
	role.ID = current.ID
	if err := s.store.UpdateRole(r.Context(), role); err != nil {
		roleError(w, err)
		return
	}
	saved, err := s.store.GetRole(r.Context(), role.ID)
	if err != nil || saved == nil {
		roleError(w, sql.ErrNoRows)
		return
	}
	jsonResponse(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRole(r.Context(), mux.Vars(r)["id"]); err != nil {
		roleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
