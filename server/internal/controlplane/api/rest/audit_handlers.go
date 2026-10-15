package rest

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// AuditLogResponse lists audit entries, newest first.
type AuditLogResponse struct {
	Entries []*models.AuditEntry `json:"entries"`
}

// SessionsResponse lists the login sessions that have not expired.
type SessionsResponse struct {
	Sessions []*models.SessionInfo `json:"sessions"`
}

const loginRoute = "/api/v1/auth/login"

// auditSkipped are routes the audit middleware leaves alone: node check-ins
// run every few minutes from every node, and the legacy VPN rule endpoints
// write their own audit entries (with the rule name).
func auditSkipped(route string) bool {
	return route == "/api/v1/nodes/{id}/checkin" || strings.HasPrefix(route, "/api/v1/firewall/vpn/")
}

// loginUsernameKey holds a *string the login handler sets to the username it
// was given, so a login entry says which account was tried.
type loginUsernameKey struct{}

// noteLoginUsername records the tried username for the audit entry (at most
// 64 characters: it is caller input).
func noteLoginUsername(r *http.Request, username string) {
	if p, ok := r.Context().Value(loginUsernameKey{}).(*string); ok {
		if len(username) > 64 {
			username = username[:64]
		}
		*p = username
	}
}

// auditMiddleware records every successful change made through the API
// (POST, PUT, PATCH, DELETE answered 2xx) and every login attempt, with the
// route template (no IDs in the action), status, user and address.
func (s *Server) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		// The login handler fills in the username it was given.
		tried := new(string)
		r = r.WithContext(context.WithValue(r.Context(), loginUsernameKey{}, tried))
		next.ServeHTTP(rec, r)
		route := r.URL.Path
		if cur := mux.CurrentRoute(r); cur != nil {
			if tpl, err := cur.GetPathTemplate(); err == nil {
				route = tpl
			}
		}
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		if auditSkipped(route) || (route != loginRoute && (status < 200 || status > 299)) {
			return
		}
		// A rate-limited login costs the caller nothing (no password check):
		// recording it would let anyone grow the table.
		if route == loginRoute && status == http.StatusTooManyRequests {
			return
		}
		action := r.Method + " " + route
		if len(action) > 50 { // firewall_audit_log.action is VARCHAR(50)
			action = action[:50]
		}
		details := map[string]any{"status": status, "path": r.URL.Path}
		if route == loginRoute && *tried != "" {
			details["username"] = *tried
		}
		if err := s.store.CreateFirewallAuditLog(context.WithoutCancel(r.Context()), action, details, clientIP(r), sessionUserID(r)); err != nil {
			slog.Warn("audit entry not written", "action", action, "error", err)
		}
	})
}

func (s *Server) registerAuditRoutes(api *mux.Router) {
	api.HandleFunc("/audit", s.handleAuditLog).Methods("GET")
	api.HandleFunc("/auth/sessions", s.handleListSessions).Methods("GET")
	api.HandleFunc("/auth/sessions/{id}", s.handleDeleteSession).Methods("DELETE")
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	var before *time.Time
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "before must be an RFC 3339 time")
			return
		}
		before = &t
	}
	// before_id (the last entry shown) keeps entries with the same time apart.
	beforeID := r.URL.Query().Get("before_id")
	if beforeID != "" {
		if _, err := uuid.Parse(beforeID); err != nil || before == nil {
			errorResponse(w, http.StatusBadRequest, "before_id must be an entry id, given with before")
			return
		}
	}
	entries, err := s.store.ListAuditLog(r.Context(), limit, before, beforeID)
	if err != nil {
		slog.Error("audit log not read", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the audit log")
		return
	}
	jsonResponse(w, http.StatusOK, AuditLogResponse{Entries: entries})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListSessions(r.Context(), time.Now())
	if err != nil {
		slog.Error("sessions not read", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the sessions")
		return
	}
	user, hash := sessionFrom(r)
	visible := sessions[:0]
	for _, si := range sessions {
		if !canSeeSession(user, si) {
			continue
		}
		si.Current = hash != "" && si.TokenHash == hash
		visible = append(visible, si)
	}
	jsonResponse(w, http.StatusOK, SessionsResponse{Sessions: visible})
}

// canSeeSession: an admin sees every session, other roles their own.
func canSeeSession(user *models.User, si *models.SessionInfo) bool {
	return user == nil || user.Role == "admin" || si.Username == user.Username
}

// handleDeleteSession ends a session (it may be the caller's own: that is a
// logout).
func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		errorResponse(w, http.StatusNotFound, "session not found")
		return
	}
	// A non-admin may end only its own sessions; another user's is 404.
	if user, _ := sessionFrom(r); user != nil && user.Role != "admin" {
		sessions, err := s.store.ListSessions(r.Context(), time.Now())
		if err != nil {
			slog.Error("sessions not read", "error", err)
			errorResponse(w, http.StatusInternalServerError, "failed to end the session")
			return
		}
		own := false
		for _, si := range sessions {
			if si.ID == id && canSeeSession(user, si) {
				own = true
			}
		}
		if !own {
			errorResponse(w, http.StatusNotFound, "session not found")
			return
		}
	}
	ok, err := s.store.DeleteSessionByID(r.Context(), id)
	if err != nil {
		slog.Error("session not deleted", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to end the session")
		return
	}
	if !ok {
		errorResponse(w, http.StatusNotFound, "session not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
