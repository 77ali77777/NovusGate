package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Panel roles (P9a), lowest first.
var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

// operatorRoutes are the changes an operator may make: networks, nodes,
// groups and VPN rules. Every other change needs an admin.
var operatorRoutes = map[string]bool{
	"POST /api/v1/networks":                     true,
	"DELETE /api/v1/networks/{id}":              true,
	"PUT /api/v1/networks/{id}/dns":             true,
	"POST /api/v1/networks/{id}/restart":        true,
	"POST /api/v1/networks/{networkId}/servers": true,
	"POST /api/v1/networks/{networkId}/sync":    true,
	"PUT /api/v1/nodes/{id}":                    true,
	"PATCH /api/v1/nodes/{id}":                  true,
	"DELETE /api/v1/nodes/{id}":                 true,
	"POST /api/v1/nodes/{id}/rotate-key":        true, // the new config is fetched with the operator-only config GET
	"POST /api/v1/nodes/{id}/checkin":           true, // with a session: the panel reports for a node
	"POST /api/v1/groups":                       true,
	"PUT /api/v1/groups/{id}":                   true,
	"DELETE /api/v1/groups/{id}":                true,
	"PUT /api/v1/groups/{id}/members":           true,
	"POST /api/v1/limits":                       true,
	"PUT /api/v1/limits/{id}":                   true,
	"DELETE /api/v1/limits/{id}":                true,
	"PUT /api/v1/limits/{id}/bindings":          true,
	"POST /api/v1/nodes/{id}/quota/reset":       true,
	"POST /api/v1/firewall/vpn/rules":           true,
	"PUT /api/v1/firewall/vpn/rules/{id}":       true,
	"DELETE /api/v1/firewall/vpn/rules/{id}":    true,
	"POST /api/v1/firewall/vpn/apply":           true,
}

// anyRoleRoutes are changes to the caller's own account.
var anyRoleRoutes = map[string]bool{
	"PUT /api/v1/auth/password": true, // the handler allows only the caller's own password
	"POST /api/v1/auth/logout":  true,
	// the handler lets a non-admin end only its own sessions
	"DELETE /api/v1/auth/sessions/{id}": true,
	"POST /api/v1/auth/step-up":         true, // the caller's own password
}

// sensitiveReads are GETs that hand out secrets, create tokens or dump the
// host firewall, with the role they need.
var sensitiveReads = map[string]string{
	"GET /api/v1/nodes/{id}/config":           "operator", // private key
	"GET /api/v1/nodes/{id}/qrcode":           "operator", // private key
	"GET /api/v1/nodes/{id}/install.sh":       "operator", // creates an enrollment token
	"GET /api/v1/backups/{name}":              "admin",    // database dump and WireGuard keys
	"GET /api/v1/debug/wireguard/{networkId}": "admin",
	"GET /api/v1/users":                       "admin",
	"GET /api/v1/roles":                       "admin", // custom roles (2026-10-20)
	"GET /api/v1/firewall/host/export":        "admin", // the whole host ruleset
	"GET /api/v1/server/services":             "admin", // server administration (P10a)
	"GET /api/v1/server/sysctl":               "admin", // server administration (P10a)
	"GET /api/v1/server/system":               "admin", // server administration (P10a)
	"GET /api/v1/server/packages":             "admin", // server administration (P10a)
	"GET /api/v1/server/packages/upgrade":     "admin", // server administration (P10a)
	"GET /api/v1/server/network":              "admin", // server administration (P10a)
	"GET /api/v1/notifications/settings":      "admin", // Telegram chat id
}

// viewerReads are the GETs every role may make. A GET in neither list needs
// an admin, and TestOperatorRoutesExist fails until it is classified.
var viewerReads = map[string]bool{
	"GET /api/v1/audit":                          true,
	"GET /api/v1/auth/me":                        true,
	"GET /api/v1/auth/sessions":                  true, // the handler shows a non-admin only its own
	"GET /api/v1/backups":                        true,
	"GET /api/v1/firewall/access-check":          true,
	"GET /api/v1/firewall/host/rules":            true,
	"GET /api/v1/firewall/policy-matrix":         true,
	"GET /api/v1/firewall/v2/history":            true,
	"GET /api/v1/firewall/v2/live":               true,
	"GET /api/v1/firewall/v2/preview":            true,
	"GET /api/v1/firewall/v2/state":              true,
	"GET /api/v1/firewall/vpn/rules":             true,
	"GET /api/v1/groups":                         true,
	"GET /api/v1/limits":                         true,
	"GET /api/v1/settings/vpn":                   true, // the network form shows the next free CIDR
	"GET /api/v1/networks":                       true,
	"GET /api/v1/networks/{id}":                  true,
	"GET /api/v1/networks/{networkId}/nodes":     true,
	"GET /api/v1/nodes/{id}":                     true,
	"GET /api/v1/nodes/{id}/traffic":             true,
	"GET /api/v1/openapi.json":                   true,
	"GET /api/v1/stats/overview":                 true,
	"GET /api/v1/system/fail2ban/ban-history":    true,
	"GET /api/v1/system/fail2ban/jail/settings":  true,
	"GET /api/v1/system/fail2ban/logs":           true,
	"GET /api/v1/system/fail2ban/permanent-bans": true,
	"GET /api/v1/system/fail2ban/ping":           true,
	"GET /api/v1/system/fail2ban/status":         true,
	"GET /api/v1/system/fail2ban/whitelist":      true,
	"GET /api/v1/system/info":                    true,
}

// requiredRole is the role a request needs.
func requiredRole(method, route string) string {
	key := method + " " + route
	switch {
	case method == http.MethodGet || method == http.MethodHead:
		if role, ok := sensitiveReads["GET "+route]; ok {
			return role
		}
		if viewerReads["GET "+route] {
			return "viewer"
		}
		return "admin"
	case anyRoleRoutes[key]:
		return "viewer"
	case operatorRoutes[key]:
		return "operator"
	}
	return "admin"
}

// roleMiddleware refuses requests the session user's role does not allow.
// Requests without a session (login, node check-in) were already decided by
// authMiddleware.
func (s *Server) roleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := sessionFrom(r)
		if user == nil {
			next.ServeHTTP(w, r)
			return
		}
		route := r.URL.Path
		if cur := mux.CurrentRoute(r); cur != nil {
			if tpl, err := cur.GetPathTemplate(); err == nil {
				route = tpl
			}
		}
		// A custom role decides by section (and its networks), never more
		// than an operator may (custom_roles.go).
		if user.Role == "custom" {
			a, err := s.loadAccess(r.Context(), user)
			if err != nil || a == nil {
				slog.Error("custom role not read", "user", user.Username, "error", err)
				errorWithCode(w, http.StatusForbidden, "forbidden", "your role could not be read")
				return
			}
			if ok, reason := s.customAllows(r, a, r.Method, route); !ok {
				errorWithCode(w, http.StatusForbidden, "forbidden", reason)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessKey{}, a)))
			return
		}
		need := requiredRole(r.Method, route)
		if roleRank[user.Role] < roleRank[need] {
			errorWithCode(w, http.StatusForbidden, "forbidden", "your role ("+user.Role+") cannot do this; it needs "+need)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MeResponse is the signed-in user, with what the role allows per section
// (none, view or edit) so the panel shows only that.
type MeResponse struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Role        string            `json:"role"` // admin, operator, viewer or custom
	RoleID      string            `json:"role_id,omitempty"`
	RoleName    string            `json:"role_name,omitempty"`
	Permissions map[string]string `json:"permissions"`
	NetworkIDs  []string          `json:"network_ids"` // custom role limited to networks; empty: all
	// ScopeMode of a custom role: all, listed or own; for own, MaxNetworks
	// is the limit and OwnedNetworks how many the user has.
	ScopeMode     string `json:"scope_mode,omitempty"`
	MaxNetworks   int    `json:"max_networks,omitempty"`
	OwnedNetworks int    `json:"owned_networks,omitempty"`
}

// SetUserRoleRequest changes a user's role: a built-in one, or custom with
// role_id.
type SetUserRoleRequest struct {
	Role   string `json:"role"`
	RoleID string `json:"role_id,omitempty"`
}

func (s *Server) registerRoleRoutes(api *mux.Router) {
	api.HandleFunc("/auth/me", s.handleMe).Methods("GET")
	api.HandleFunc("/users/{id}/role", s.handleSetUserRole).Methods("PUT")
	api.HandleFunc("/networks/{id}/owner", s.handleSetNetworkOwner).Methods("PUT")
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := sessionFrom(r)
	if user == nil {
		errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}
	me := MeResponse{ID: user.ID, Username: user.Username, Role: user.Role, NetworkIDs: []string{}}
	if a := accessFrom(r); a != nil {
		me.RoleID, me.RoleName, me.Permissions, me.NetworkIDs = a.role.ID, a.role.Name, a.perms, a.role.NetworkIDs
		me.ScopeMode = scopeMode(a.role)
		if a.own {
			me.MaxNetworks, me.OwnedNetworks = a.role.MaxNetworks, len(a.networks)
		}
	} else {
		me.Permissions = builtInPermissions(user.Role)
	}
	jsonResponse(w, http.StatusOK, me)
}

func (s *Server) handleSetUserRole(w http.ResponseWriter, r *http.Request) {
	var req SetUserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	id := mux.Vars(r)["id"]
	switch {
	case req.Role == "custom":
		if role, err := s.store.GetRole(r.Context(), req.RoleID); err != nil || role == nil {
			errorWithCode(w, http.StatusBadRequest, "invalid_role", "role_id must name a custom role")
			return
		}
		if err := s.store.SetUserCustomRole(r.Context(), id, req.RoleID); err != nil {
			userRoleError(w, err)
			return
		}
	case store.ValidRole(req.Role):
		if err := s.store.SetUserRole(r.Context(), id, req.Role); err != nil {
			userRoleError(w, err)
			return
		}
	default:
		errorResponse(w, http.StatusBadRequest, "role must be admin, operator, viewer or custom (with role_id)")
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		userRoleError(w, err)
		return
	}
	// SetUserRole accepted id, so it is a UUID; compare the stored spelling.
	canonical := uuid.MustParse(id).String()
	for _, u := range users {
		if u.ID == canonical {
			jsonResponse(w, http.StatusOK, u)
			return
		}
	}
	errorResponse(w, http.StatusNotFound, "user not found")
}

// SetNetworkOwnerRequest hands a network to a user; null leaves it without
// an owner.
type SetNetworkOwnerRequest struct {
	UserID *string `json:"user_id"`
}

func (s *Server) handleSetNetworkOwner(w http.ResponseWriter, r *http.Request) {
	var req SetNetworkOwnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	id := mux.Vars(r)["id"]
	if err := s.store.SetNetworkOwner(r.Context(), id, req.UserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errorResponse(w, http.StatusNotFound, "network or user not found")
			return
		}
		slog.Error("network owner change failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to change the owner")
		return
	}
	network, err := s.store.GetNetwork(r.Context(), id)
	if err != nil || network == nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	jsonResponse(w, http.StatusOK, network)
}

func userRoleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		errorWithCode(w, http.StatusConflict, "last_admin", err.Error())
	case errors.Is(err, store.ErrRoleNotFound):
		errorWithCode(w, http.StatusBadRequest, "invalid_role", "role_id must name a custom role")
	case errors.Is(err, sql.ErrNoRows):
		errorResponse(w, http.StatusNotFound, "user not found")
	default:
		slog.Error("user change failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to change the user")
	}
}

// ensure the model is used for the OpenAPI document
var _ = models.User{}
