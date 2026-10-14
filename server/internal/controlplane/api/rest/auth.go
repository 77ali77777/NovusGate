package rest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"golang.org/x/crypto/bcrypt"
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
// for the public paths and an enrollment checkin.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	user, hash := sessionFrom(r)
	if user == nil {
		errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}
	if err := s.store.DeleteSession(r.Context(), hash); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to log out")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// comparePassword checks a password against a bcrypt hash (replaced in tests).
var comparePassword = bcrypt.CompareHashAndPassword

// dummyPasswordHash is compared for unknown usernames, so they take as long
// as a wrong password and do not reveal which usernames exist.
var dummyPasswordHash, _ = bcrypt.GenerateFromPassword([]byte("novusgate-no-such-user"), bcrypt.DefaultCost)

// loginLimiter counts login attempts per client key in a sliding window; a
// successful login removes its own attempt, so in effect it limits failures.
type loginLimiter struct {
	mu        sync.Mutex
	max       int
	window    time.Duration
	fails     map[string][]time.Time
	lastPrune time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, fails: map[string][]time.Time{}}
}

// maxTrackedIPs bounds the number of client keys the limiter remembers.
const maxTrackedIPs = 10000

// loginLimit guards POST /auth/login (replaced in tests).
var loginLimit = newLoginLimiter(10, 15*time.Minute)

// limiterKey is the client's IPv4 address, or its IPv6 /64: one host can
// pick any address in its /64, so counting single addresses is no limit.
func limiterKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Unmap().Is4() {
		return ip
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// recent drops attempts older than the window; callers hold mu.
func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	kept := l.fails[key][:0]
	for _, at := range l.fails[key] {
		if now.Sub(at) < l.window {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = kept
	return kept
}

// prune drops expired keys at most once a minute, then the keys with the
// oldest last attempt while the map is over its cap; callers hold mu.
func (l *loginLimiter) prune(now time.Time) {
	if len(l.fails) < maxTrackedIPs {
		return
	}
	if now.Sub(l.lastPrune) >= time.Minute {
		l.lastPrune = now
		for key := range l.fails {
			l.recent(key, now)
		}
	}
	for len(l.fails) >= maxTrackedIPs {
		oldest, oldestAt := "", now
		for key, f := range l.fails {
			if last := f[len(f)-1]; !last.After(oldestAt) {
				oldest, oldestAt = key, last
			}
		}
		delete(l.fails, oldest)
	}
}

// begin counts a login attempt from key unless key is over the limit, in
// which case it reports how long until it is not. Checking and counting
// happen under one lock, so concurrent attempts cannot all pass while
// bcrypt runs.
func (l *loginLimiter) begin(key string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.recent(key, now)
	if len(f) >= l.max {
		return l.window - now.Sub(f[len(f)-l.max]), false
	}
	if f == nil {
		l.prune(now)
	}
	l.fails[key] = append(f, now)
	return 0, true
}

// succeed removes the attempt a successful login counted; earlier failures
// still count.
func (l *loginLimiter) succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.fails[key]; len(f) > 1 {
		l.fails[key] = f[:len(f)-1]
	} else {
		delete(l.fails, key)
	}
}

// clientIP is the request's remote address without the port. Behind the
// panel's nginx (a loopback peer) it is the X-Real-IP that nginx sets;
// any other client cannot choose its address with that header.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if real := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); real != nil {
			return real.String()
		}
	}
	return host
}

// sessionUserID is the panel user's ID, or "" without a session.
func sessionUserID(r *http.Request) string {
	if user, _ := sessionFrom(r); user != nil {
		return user.ID
	}
	return ""
}
