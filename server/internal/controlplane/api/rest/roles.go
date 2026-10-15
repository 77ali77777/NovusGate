package rest

import (
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
	"POST /api/v1/networks/{networkId}/servers": true,
	"POST /api/v1/networks/{networkId}/sync":    true,
	"PUT /api/v1/nodes/{id}":                    true,
	"PATCH /api/v1/nodes/{id}":                  true,
	"DELETE /api/v1/nodes/{id}":                 true,
	"POST /api/v1/groups":                       true,
	"PUT /api/v1/groups/{id}":                   true,
	"DELETE /api/v1/groups/{id}":                true,
	"PUT /api/v1/groups/{id}/members":           true,
	"POST /api/v1/firewall/vpn/rules":           true,
	"PUT /api/v1/firewall/vpn/rules/{id}":       true,
	"DELETE /api/v1/firewall/vpn/rules/{id}":    true,
	"POST /api/v1/firewall/vpn/apply":           true,
}

// anyRoleRoutes are changes to the caller's own account.
var anyRoleRoutes = map[string]bool{
	"PUT /api/v1/auth/password": true, // the handler allows only the caller's own password
	"POST /api/v1/auth/logout":  true,
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
	"GET /api/v1/auth/sessions":               "admin",
	"GET /api/v1/firewall/host/export":        "admin", // the whole host ruleset
	"GET /api/v1/notifications/settings":      "admin", // Telegram chat id
}

// viewerReads are the GETs every role may make. A GET in neither list needs
// an admin, and TestOperatorRoutesExist fails until it is classified.
var viewerReads = map[string]bool{
	"GET /api/v1/audit":                            true,
	"GET /api/v1/auth/me":                          true,
	"GET /api/v1/backups":                          true,
	"GET /api/v1/firewall/host/rules":              true,
	"GET /api/v1/firewall/policy-matrix":           true,
	"GET /api/v1/firewall/v2/history":              true,
	"GET /api/v1/firewall/v2/live":                 true,
	"GET /api/v1/firewall/v2/preview":              true,
	"GET /api/v1/firewall/v2/state":                true,
	"GET /api/v1/firewall/vpn/rules":               true,
	"GET /api/v1/groups":                           true,
	"GET /api/v1/networks":                         true,
	"GET /api/v1/networks/{id}":                    true,
	"GET /api/v1/networks/{networkId}/nodes":       true,
	"GET /api/v1/nodes/{id}":                       true,
	"GET /api/v1/nodes/{id}/traffic":               true,
	"GET /api/v1/openapi.json":                     true,
	"GET /api/v1/stats/overview":                   true,
	"GET /api/v1/system/fail2ban/ban-history":      true,
	"GET /api/v1/system/fail2ban/jail/settings":    true,
	"GET /api/v1/system/fail2ban/logs":             true,
	"GET /api/v1/system/fail2ban/permanent-bans":   true,
	"GET /api/v1/system/fail2ban/ping":             true,
	"GET /api/v1/system/fail2ban/status":           true,
	"GET /api/v1/system/fail2ban/whitelist":        true,
	"GET /api/v1/system/info":                      true,
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
		need := requiredRole(r.Method, route)
		if roleRank[user.Role] < roleRank[need] {
			errorWithCode(w, http.StatusForbidden, "forbidden", "your role ("+user.Role+") cannot do this; it needs "+need)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MeResponse is the signed-in user.
type MeResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// SetUserRoleRequest changes a user's role.
type SetUserRoleRequest struct {
	Role string `json:"role"`
}

func (s *Server) registerRoleRoutes(api *mux.Router) {
	api.HandleFunc("/auth/me", s.handleMe).Methods("GET")
	api.HandleFunc("/users/{id}/role", s.handleSetUserRole).Methods("PUT")
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := sessionFrom(r)
	if user == nil {
		errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}
	jsonResponse(w, http.StatusOK, MeResponse{ID: user.ID, Username: user.Username, Role: user.Role})
}

func (s *Server) handleSetUserRole(w http.ResponseWriter, r *http.Request) {
	var req SetUserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if !store.ValidRole(req.Role) {
		errorResponse(w, http.StatusBadRequest, "role must be admin, operator or viewer")
		return
	}
	id := mux.Vars(r)["id"]
	if err := s.store.SetUserRole(r.Context(), id, req.Role); err != nil {
		userRoleError(w, err)
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

func userRoleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		errorWithCode(w, http.StatusConflict, "last_admin", err.Error())
	case errors.Is(err, sql.ErrNoRows):
		errorResponse(w, http.StatusNotFound, "user not found")
	default:
		slog.Error("user change failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to change the user")
	}
}

// ensure the model is used for the OpenAPI document
var _ = models.User{}
