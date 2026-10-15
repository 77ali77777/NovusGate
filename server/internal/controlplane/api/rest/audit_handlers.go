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
		action := r.Method + " " + route
		if len(action) > 50 { // firewall_audit_log.action is VARCHAR(50)
			action = action[:50]
		}
		details := map[string]any{"status": status, "path": r.URL.Path}
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
	entries, err := s.store.ListAuditLog(r.Context(), limit, before)
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
	_, hash := sessionFrom(r)
	for _, si := range sessions {
		si.Current = hash != "" && si.TokenHash == hash
	}
	jsonResponse(w, http.StatusOK, SessionsResponse{Sessions: sessions})
}

// handleDeleteSession ends a session (it may be the caller's own: that is a
// logout).
func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		errorResponse(w, http.StatusNotFound, "session not found")
		return
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
