package rest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
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
		if publicPaths[r.URL.Path] || isEnrollmentCheckin(r) { // the checkin handler validates the token
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

// loginLimiter counts login attempts per client IP in a sliding window; a
// successful login clears them, so in effect it limits failures.
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, fails: map[string][]time.Time{}}
}

// maxTrackedIPs bounds the limiter map before it prunes expired entries.
const maxTrackedIPs = 10000

// loginLimit guards POST /auth/login (replaced in tests).
var loginLimit = newLoginLimiter(10, 15*time.Minute)

// recent drops failures older than the window; callers hold mu.
func (l *loginLimiter) recent(ip string, now time.Time) []time.Time {
	kept := l.fails[ip][:0]
	for _, at := range l.fails[ip] {
		if now.Sub(at) < l.window {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, ip)
		return nil
	}
	l.fails[ip] = kept
	return kept
}

// begin counts a login attempt from ip unless ip is over the limit, in which
// case it reports how long until it is not. Checking and counting happen
// under one lock, so concurrent attempts cannot all pass while bcrypt runs;
// a successful login clears the count with reset.
func (l *loginLimiter) begin(ip string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > maxTrackedIPs { // many distinct IPs: drop the ones whose attempts expired
		for other := range l.fails {
			l.recent(other, now)
		}
	}
	f := l.recent(ip, now)
	if len(f) >= l.max {
		return l.window - now.Sub(f[len(f)-l.max]), false
	}
	l.fails[ip] = append(f, now)
	return 0, true
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// clientIP is the request's remote address without the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
