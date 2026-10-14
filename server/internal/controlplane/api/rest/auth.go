package rest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// sessionTTL is how long a login lasts; it is not extended by use.
const sessionTTL = 24 * time.Hour

// authNow is the clock used for session expiry (replaced in tests).
var authNow = time.Now

type sessionKey struct{}

type session struct {
	user *models.User
	hash string
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// publicPaths skip authentication; exact matches only.
var publicPaths = map[string]bool{"/health": true, "/api/v1/auth/login": true}

// sessionFrom returns the authenticated user and the session's token hash.
func sessionFrom(r *http.Request) (*models.User, string) {
	if sess, ok := r.Context().Value(sessionKey{}).(session); ok {
		return sess.user, sess.hash
	}
	return nil, ""
}

// authMiddleware requires a bearer token of an unexpired session, except
// for the public paths and CORS preflights.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			errorResponse(w, http.StatusUnauthorized, "missing authorization header")
			return
		}
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok {
			errorResponse(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}
		hash := hashToken(token)
		now := authNow()
		user, err := s.store.SessionUser(r.Context(), hash, now)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to check session")
			return
		}
		if user == nil {
			errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
			return
		}
		s.store.TouchSession(r.Context(), hash, now) // best effort: last_used_at is informational
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session{user, hash})))
	})
}

// handleLogout revokes the caller's session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_, hash := sessionFrom(r)
	if err := s.store.DeleteSession(r.Context(), hash); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to log out")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
