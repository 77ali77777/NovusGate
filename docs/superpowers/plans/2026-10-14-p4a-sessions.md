# P4a Sessions and Auth Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single per-process admin token with per-user sessions stored in PostgreSQL. Add logout, revoke sessions on user deletion and password change, rate-limit login, and fix the auth bugs found in the P4 inventory.

**Architecture:**
- A new `sessions` table stores only the SHA-256 hash of each bearer token.
- `AuthMiddleware` becomes a `Server` method. It looks the hash up, rejects expired sessions, and puts the session's user in the request context.
- Login creates a session. Logout deletes it.
- Deleting a user cascades to its sessions (foreign key).
- Changing a password revokes the user's other sessions.
- A small in-memory limiter counts failed logins per client IP.

**Tech Stack:** Go 1.23, gorilla/mux, PostgreSQL 16, React/TypeScript (web).

**Spec:**
- Master spec `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` §4.3 (sessions, logout, user deletion revokes, login rate limit) and §7 B15.
- User approval on 2026-10-14: "P4 spec-dəki kimi".
- P4 is split:
  - **P4a:** this plan.
  - **P4b:** enrollment token, public install.sh/checkin, nginx `/api` proxy, same-origin web, B10, B23.
  - **P4c:** AES-GCM node keys, hiding `wireguard_private_key`, audit `user_id`.

## Global Constraints

- **Decisions this plan makes** (the spec names the columns, not the values):
  - session lifetime is fixed at 24 h from login (`sessionTTL`); `last_used_at` is updated at most once a minute;
  - tokens are 32 random bytes, hex-encoded (64 characters);
  - only `sha256(token)` is stored;
  - login limit: 10 failed attempts per client IP in 15 minutes → `429 too_many_attempts` with `Retry-After`; a successful login clears that IP's counter.
- **Contract changes (approved with P4):**
  - `POST /auth/login` now returns the real username and a per-session token;
  - new `POST /api/v1/auth/logout` → 204;
  - `PUT /auth/password` returns `400 invalid_old_password` (was 401, B15) and changes the session user's password. A body `username` that names another user → `403 forbidden`;
  - an expired or revoked token → `401 invalid_token`;
  - login rate limit → 429.
- **Unchanged:**
  - `X-API-Key` handling (P4b revisits it);
  - CORS headers (P4b removes them with the same-origin proxy).
- **Auth bypass:**
  - only the exact paths `/health` and `/api/v1/auth/login` skip auth;
  - the old `HasSuffix(path, "/login")` let any path ending in `/login` through.
- **Migrations:** additive. `007_sessions.sql` ships with `migrations_rollback/007_sessions.down.sql`.
- **Environment:**
  - Go runs only in Docker: `bash server/scripts/test-with-postgres.sh`;
  - snapshots are updated with `bash server/scripts/update-contracts.sh`;
  - web is checked with `npx tsc --noEmit` and `npx biome check` from `web/`.
- **Commits:** no Co-Authored-By / Claude / Anthropic lines. Comments in English, docs in Azerbaijani.

## Review Focus

1. **A token that is valid now but expired later.**
   - Expected: 401 after `expires_at`.
   - Pinned by `TestExpiredSessionIsRejected`, which moves the clock.
2. **A revoked token.** Revocation happens on logout, user deletion and password change.
   - Expected: 401 on the next request.
   - Pinned by `TestLogoutRevokesToken`, `TestDeletingUserRevokesSessions` and `TestPasswordChangeRevokesOtherSessions`.
3. **Paths that merely end in `/login`, such as `/api/v1/networks/login`.**
   - Expected: 401 without a token.
   - Pinned by `TestOnlyExactPublicPathsSkipAuth`.
4. **The login limiter.**
   - Expected: it never blocks a correct password before the limit is reached, and it does block after it, even when the 11th attempt has the correct password.
   - Pinned by `TestLoginRateLimit`.
5. **Password change.**
   - Expected: it cannot change another account by naming it in the body.
   - Pinned by `TestPasswordChangeIsForSessionUser`.

---

## File Structure

| File | Responsibility |
|---|---|
| `server/internal/controlplane/store/migrations_sql/007_sessions.sql` (create) | sessions table |
| `server/internal/controlplane/store/migrations_rollback/007_sessions.down.sql` (create) | rollback |
| `server/internal/controlplane/store/sessions.go` (create) | session store functions |
| `server/internal/controlplane/store/sessions_test.go` (create) | store tests |
| `server/internal/controlplane/api/rest/auth.go` (create) | tokens, `authMiddleware`, logout, limiter, context user |
| `server/internal/controlplane/api/rest/auth_test.go` (create) | auth behaviour tests |
| `handlers.go` (modify) | remove the admin globals, `init`, old `AuthMiddleware`; login, password |
| `contract_test.go`, `firewall_engine_test.go` (modify) | test sessions instead of the global token |
| `openapi.go` (modify) | logout docOp |
| `web/src/App.tsx`, `web/src/components/Layout.tsx`, `web/src/api/client.ts` (modify) | store the returned username, call logout |

---

### Task 1: Sessions table and store

**Files:** create `007_sessions.sql`, `007_sessions.down.sql`, `store/sessions.go`, `store/sessions_test.go`.

**Interfaces — Produces:**
- `func (s *Store) CreateSession(ctx context.Context, userID, tokenHash string, now time.Time, ttl time.Duration) error`
- `func (s *Store) SessionUser(ctx context.Context, tokenHash string, now time.Time) (*models.User, error)`: nil, nil when missing or expired
- `func (s *Store) TouchSession(ctx context.Context, tokenHash string, now time.Time) error`: sets `last_used_at` when it is older than a minute
- `func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error`
- `func (s *Store) DeleteUserSessions(ctx context.Context, userID, exceptHash string) error`
- `func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error`

- [ ] **Step 1: Write the failing store test** (`sessions_test.go`)

```go
package store

import (
	"context"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestSessionsLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM users WHERE username LIKE 'sess-%'")
	u := &models.User{Username: "sess-a", PasswordHash: "x"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteUser(context.Background(), u.ID) })
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, h := range []string{"h1", "h2"} {
		if err := s.CreateSession(ctx, u.ID, h, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.SessionUser(ctx, "h1", now.Add(59*time.Minute)); err != nil || got == nil || got.Username != "sess-a" {
		t.Fatalf("valid session = %v, %v", got, err)
	}
	if got, _ := s.SessionUser(ctx, "h1", now.Add(61*time.Minute)); got != nil {
		t.Fatal("an expired session must not resolve")
	}
	if got, _ := s.SessionUser(ctx, "nope", now); got != nil {
		t.Fatal("an unknown hash must not resolve")
	}
	if err := s.DeleteUserSessions(ctx, u.ID, "h2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SessionUser(ctx, "h1", now); got != nil {
		t.Fatal("h1 must be revoked")
	}
	if got, _ := s.SessionUser(ctx, "h2", now); got == nil {
		t.Fatal("the excepted session must survive")
	}
	if err := s.DeleteSession(ctx, "h2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SessionUser(ctx, "h2", now); got != nil {
		t.Fatal("h2 must be deleted")
	}
	// Deleting the user cascades to its sessions.
	s.CreateSession(ctx, u.ID, "h3", now, time.Hour)
	s.DeleteUser(ctx, u.ID)
	var n int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM sessions WHERE token_hash = 'h3'").Scan(&n)
	if n != 0 {
		t.Fatal("user deletion must remove its sessions")
	}
}
```

- [ ] **Step 2: Run and verify it fails.** Run: `bash server/scripts/test-with-postgres.sh`. Expected: a build failure, `s.CreateSession undefined`.

- [ ] **Step 3: Implement**

`007_sessions.sql`:

```sql
-- Migration: 007_sessions.sql
-- Purpose: per-user login sessions (P4a). Only the SHA-256 of a token is stored.
-- rollback: internal/controlplane/store/migrations_rollback/007_sessions.down.sql
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
```

`007_sessions.down.sql`:

```sql
-- Rollback for 007_sessions.sql. Run manually with psql. Every logged-in
-- panel user is logged out; the old binary does not read this table.
BEGIN;
DROP TABLE IF EXISTS sessions;
DELETE FROM schema_migrations WHERE version = '007_sessions.sql';
COMMIT;
```

`store/sessions.go`:

```go
package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// CreateSession stores a login session; only the token's hash is kept.
func (s *Store) CreateSession(ctx context.Context, userID, tokenHash string, now time.Time, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at)
		VALUES ($1, $2, $3, $4, $3)`, tokenHash, userID, now, now.Add(ttl))
	return err
}

// SessionUser returns the user of an unexpired session, or nil.
func (s *Store) SessionUser(ctx context.Context, tokenHash string, now time.Time) (*models.User, error) {
	var u models.User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now).Scan(&u.ID, &u.Username, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// TouchSession records use of a session, at most once a minute.
func (s *Store) TouchSession(ctx context.Context, tokenHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET last_used_at = $2
		WHERE token_hash = $1 AND last_used_at < $3`, tokenHash, now, now.Add(-time.Minute))
	return err
}

// DeleteSession revokes one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUserSessions revokes every session of a user except exceptHash.
func (s *Store) DeleteUserSessions(ctx context.Context, userID, exceptHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, exceptHash)
	return err
}

// DeleteExpiredSessions removes sessions past their expiry.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	return err
}
```

- [ ] **Step 4: Run and verify.** Run: `bash server/scripts/test-with-postgres.sh`. Expected: all `ok`.

- [ ] **Step 5: Commit.** `git commit -m "feat: add the sessions table and store"`.

---

### Task 2: Session auth, login and logout

**Files:** create `api/rest/auth.go` and `api/rest/auth_test.go`; modify `handlers.go`, `contract_test.go`, `firewall_engine_test.go`, `openapi.go`, snapshots.

**Interfaces:**
- Consumes: Task 1 store functions.
- Produces:
  - `const sessionTTL = 24 * time.Hour`
  - `var authNow = time.Now` (replaced in tests)
  - `func hashToken(token string) string`
  - `func newSessionToken() (string, error)`
  - `func (s *Server) authMiddleware(next http.Handler) http.Handler`
  - `func sessionFrom(r *http.Request) (*models.User, string)` (user, token hash)
  - `func (s *Server) handleLogout(w, r)`
  - test helper `func testSession(t *testing.T, st *store.Store, username string) string`, which sets the package test variable `adminToken`.

- [ ] **Step 1: Write the failing tests** (`auth_test.go`)

```go
package rest

import (
	"net/http"
	"testing"
	"time"
)

func TestLogoutRevokesToken(t *testing.T) {
	s, _, _ := newContractServer(t)
	if rec := callAs(t, s, "POST", "/api/v1/auth/logout", "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout = %d, want 401", rec.Code)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	s, _, _ := newContractServer(t)
	orig := authNow
	t.Cleanup(func() { authNow = orig })
	authNow = func() time.Time { return time.Now().Add(sessionTTL + time.Minute) }
	rec := callAs(t, s, "GET", "/api/v1/networks", "", true)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401", rec.Code)
	}
}

func TestOnlyExactPublicPathsSkipAuth(t *testing.T) {
	s, _, _ := newContractServer(t)
	for _, p := range []string{"/api/v1/networks/login", "/api/v1/nodes/x/login"} {
		if rec := callAs(t, s, "GET", p, "", false); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token = %d, want 401", p, rec.Code)
		}
	}
}

func TestLoginCreatesASessionForThatUser(t *testing.T) {
	s, _, _ := newContractServer(t)
	rec := callAs(t, s, "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"contract-pw-1"}`, false)
	var body LoginResponse
	decodeJSON(t, rec, &body)
	if body.Username != "contract-user" || len(body.Token) != 64 {
		t.Fatalf("login = %+v", body)
	}
	adminToken = body.Token
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != http.StatusOK {
		t.Fatalf("the new token must work: %d", rec.Code)
	}
}
```

`decodeJSON` is added to `auth_test.go` if no such helper exists. Check first: `grep -n "func decodeJSON" *_test.go`.

```go
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %d %s: %v", rec.Code, rec.Body, err)
	}
}
```

Test-side token: `adminToken` stops being a production global. Declare it in `contract_test.go` as `var adminToken string // the test session's bearer token`.
- `newContractServer` creates `contract-user` itself (moved from `seedContract`) and calls `adminToken = testSession(t, st, "contract-user")`.
- `newEngineServer` calls `adminToken = testSession(t, st, "engine-admin")`. The helper creates the user if it is missing.
- `normalizeBody` additionally replaces any 64-hex token value: add `tokenRe = regexp.MustCompile(`"token": ?"[0-9a-f]{64}"`)` → `"token":"<token>"`.

```go
// testSession creates (or reuses) a user and a session for it, and returns
// the bearer token.
func testSession(t *testing.T, st *store.Store, username string) string {
	t.Helper()
	ctx := context.Background()
	u, err := st.GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		hash, _ := bcrypt.GenerateFromPassword([]byte("contract-pw-1"), bcrypt.MinCost)
		u = &models.User{Username: username, PasswordHash: string(hash)}
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	token, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, u.ID, hashToken(token), time.Now(), sessionTTL); err != nil {
		t.Fatal(err)
	}
	return token
}
```

`newEngineServer` must delete `engine-admin` in `t.Cleanup` (sessions cascade).

- [ ] **Step 2: Run and verify it fails.** Expected: a build failure (`newSessionToken`, `sessionTTL`, `authNow` and `hashToken` are undefined).

- [ ] **Step 3: Implement** (`auth.go`)

```go
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
```

Changes in `handlers.go`:
- Delete the admin globals block's `adminUsername`, `adminPassword` and `adminToken`, and the `init()` that generated the token. Keep `apiKey` and `getEnvOrDefault`.
- Delete the old `AuthMiddleware`.
- `setupRoutes`: `s.router.Use(LoggingMiddleware, RecoverMiddleware, APIKeyMiddleware, s.authMiddleware)`, and register `api.HandleFunc("/auth/logout", s.handleLogout).Methods("POST")`.
- `APIKeyMiddleware`: replace the `/health || HasSuffix("/login")` check with `publicPaths[r.URL.Path]`.
- `handleLogin`, success path:

```go
	s.store.DeleteExpiredSessions(r.Context(), authNow()) // housekeeping; a failure only leaves old rows
	token, err := newSessionToken()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	if err := s.store.CreateSession(r.Context(), user.ID, hashToken(token), authNow(), sessionTTL); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	jsonResponse(w, http.StatusOK, LoginResponse{Token: token, Username: user.Username})
```

Clean up unused imports (`crypto/subtle` stays for `APIKeyMiddleware`). In `openapi.go`, add after the password docOp:

```go
	{"POST", "/api/v1/auth/logout", "Log out (revokes this session)", "auth", nil, 204, nil, false},
```

Contract cases in `TestContract`: add `{"logout", "POST", "/api/v1/auth/logout", "", true}` as the **last** case (it revokes the token).

- [ ] **Step 4: Run, update snapshots, verify.**
  - Run `bash server/scripts/update-contracts.sh`, then `git diff testdata/contract`.
  - Expected:
    - `login_ok.json`: `"username": "admin"` → `"contract-user"`, approved;
    - `unauthorized.json` unchanged;
    - new `logout.json`;
    - `openapi.json` gains logout;
    - nothing else.
  - Then run `bash server/scripts/test-with-postgres.sh`. Expected: all `ok`.

- [ ] **Step 5: Commit.** `git commit -m "feat: per-user sessions with logout"`.

---

### Task 3: Login rate limit

**Files:** modify `auth.go`, `auth_test.go`, `handlers.go` (`handleLogin`), `openapi.go` (no change: 429 falls under `default`), `docs/api.md`.

**Interfaces — Produces:**
- `type loginLimiter struct`
- `func newLoginLimiter(max int, window time.Duration) *loginLimiter`
- `(l) blocked(ip string, now time.Time) (time.Duration, bool)`
- `(l) fail(ip string, now time.Time)`
- `(l) reset(ip string)`
- `var loginLimit = newLoginLimiter(10, 15*time.Minute)`

- [ ] **Step 1: Failing test**

```go
func TestLoginRateLimit(t *testing.T) {
	s, _, _ := newContractServer(t)
	orig := loginLimit
	t.Cleanup(func() { loginLimit = orig })
	loginLimit = newLoginLimiter(3, 15*time.Minute)
	good := `{"username":"contract-user","password":"contract-pw-1"}`
	bad := `{"username":"contract-user","password":"wrong"}`
	if rec := callAs(t, s, "POST", "/api/v1/auth/login", bad, false); rec.Code != 401 {
		t.Fatalf("first bad = %d", rec.Code)
	}
	if rec := callAs(t, s, "POST", "/api/v1/auth/login", good, false); rec.Code != 200 {
		t.Fatalf("a good login under the limit = %d", rec.Code)
	}
	for i := 0; i < 3; i++ {
		callAs(t, s, "POST", "/api/v1/auth/login", bad, false)
	}
	rec := callAs(t, s, "POST", "/api/v1/auth/login", good, false)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit = %d %v, want 429 with Retry-After", rec.Code, rec.Header())
	}
	assertErrorCode(t, rec, "too_many_attempts")
}
```

Check `grep -n "func assertErrorCode" *_test.go`. If it does not exist, decode `{"error":{"code"}}` inline.

- [ ] **Step 2: Run and verify it fails.** Expected: a build failure (`loginLimit`, `newLoginLimiter` undefined).

- [ ] **Step 3: Implement** (append to `auth.go`)

```go
// loginLimiter counts failed logins per client IP in a sliding window.
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, fails: map[string][]time.Time{}}
}

// loginLimit guards POST /auth/login (replaced in tests).
var loginLimit = newLoginLimiter(10, 15*time.Minute)

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

// blocked reports whether ip is over the limit and how long until it is not.
func (l *loginLimiter) blocked(ip string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.recent(ip, now)
	if len(f) < l.max {
		return 0, false
	}
	return l.window - now.Sub(f[0]), true
}

func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[ip] = append(l.recent(ip, now), now)
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
```

In `handleLogin`, after the OPTIONS check:

```go
	ip, now := clientIP(r), authNow()
	if wait, blocked := loginLimit.blocked(ip, now); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		errorWithCode(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed logins, try again later")
		return
	}
```

Call `loginLimit.fail(ip, now)` before each of the two `invalid_credentials` responses, and `loginLimit.reset(ip)` on success. P4b replaces `clientIP` with trusted-proxy handling.

- [ ] **Step 4: Run and verify.** Expected: all `ok`. Add `too_many_attempts` (429) to the code list in `docs/api.md`.

- [ ] **Step 5: Commit.** `git commit -m "feat: rate-limit failed logins per IP"`.

---

### Task 4: Password change for the session user, B15, revocation; web

**Files:** modify `handlers.go` (`handleUpdatePassword`), `auth_test.go`, `error_codes_test.go`, `web/src/App.tsx`, `web/src/components/Layout.tsx`, `web/src/api/client.ts`.

- [ ] **Step 1: Failing tests**

```go
func TestPasswordChangeIsForSessionUser(t *testing.T) {
	s, st, _ := newContractServer(t)
	testSession(t, st, "contract-other") // a second account
	body := `{"username":"contract-other","oldPassword":"contract-pw-1","newPassword":"x-new-pw"}`
	rec := callAs(t, s, "PUT", "/api/v1/auth/password", body, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("changing another account = %d, want 403", rec.Code)
	}
}

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	s, st, _ := newContractServer(t)
	other := testSession(t, st, "contract-user") // a second session of the same user
	mine := adminToken
	rec := callAs(t, s, "PUT", "/api/v1/auth/password", `{"oldPassword":"contract-pw-1","newPassword":"contract-pw-2"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("password = %d %s", rec.Code, rec.Body)
	}
	adminToken = other
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the other session = %d, want 401", rec.Code)
	}
	adminToken = mine
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != http.StatusOK {
		t.Fatalf("the current session = %d, want 200", rec.Code)
	}
}

func TestDeletingUserRevokesSessions(t *testing.T) {
	s, st, _ := newContractServer(t)
	victim := testSession(t, st, "contract-gone")
	u, _ := st.GetUserByUsername(context.Background(), "contract-gone")
	if rec := callAs(t, s, "DELETE", "/api/v1/users/"+u.ID, "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	adminToken = victim
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user's session = %d, want 401", rec.Code)
	}
}
```

In `error_codes_test.go`, the old-password case changes from 401 to `400 invalid_old_password`. Its request body sends the session user's username.

- [ ] **Step 2: Run and verify it fails.**
  - Expected: `TestPasswordChangeIsForSessionUser` gets 200 or 401, not 403.
  - Expected: the error-code case gets 401, not 400.
  - Expected: `TestPasswordChangeRevokesOtherSessions` sees 200 on the other session.
  - `TestDeletingUserRevokesSessions` may already pass through the FK cascade. It is a pin, not a RED. Write that in the ledger.

- [ ] **Step 3: Implement.** `handleUpdatePassword`:

```go
	user, hash := sessionFrom(r)
	if req.Username != "" && req.Username != user.Username {
		errorWithCode(w, http.StatusForbidden, "forbidden", "you can only change your own password")
		return
	}
	stored, err := s.store.GetUserByUsername(r.Context(), user.Username)
	if err != nil || stored == nil {
		errorResponse(w, http.StatusInternalServerError, "failed to check user")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte(req.OldPassword)); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_old_password", "invalid old password") // 400: a 401 logs the panel out (B15)
		return
	}
	// … hash and UpdateUserPassword(user.Username, …) as before …
	if err := s.store.DeleteUserSessions(r.Context(), user.ID, hash); err != nil {
		errorResponse(w, http.StatusInternalServerError, "password changed, but other sessions could not be revoked")
		return
	}
```

Web:
- `App.tsx` login: `localStorage.setItem('auth_username', data.username)`.
- `client.ts`: add the method

```ts
  async logout(): Promise<void> {
    await this.client.post('/auth/logout')
  }
```

- `Layout.tsx`: the logout button runs `api.logout().catch(() => undefined).finally(() => { localStorage.removeItem('auth_token'); localStorage.removeItem('auth_username'); window.location.href = '/login' })`. A failed logout still clears the local session. Check how Layout imports the client: `grep -n "import.*api" web/src/components/Layout.tsx web/src/api/client.ts | tail`.

- [ ] **Step 4: Run and verify.**
  - Go: all `ok`.
  - From `web/`: `npx tsc --noEmit` and `npx biome check src/App.tsx src/components/Layout.tsx src/api/client.ts`. Expected: no new errors versus `git stash`-free baseline. Record the baseline output first.
  - `update-contracts.sh`: `host_password.json` stays 200 (its body names contract-user, the session user).

- [ ] **Step 5: Commit.** `git commit -m "fix: password change acts on the session user (B15)"`.

---

### Task 5: Documentation

- [ ] Update the docs:
  - **`docs/api.md`:**
    - the auth section covers sessions, logout, the 24 h lifetime, rate limit and 429;
    - password change (400, 403, other sessions revoked);
    - exact public paths.
  - **`docs/security.md`:** create it if it is missing (`ls docs`). Cover session storage (hash only), revocation and the login limit.
  - **`docs/data-model.md`:** create or update. Cover the `sessions` table and its rollback.
  - **`docs/active-context.md`:** a session block and a table row.
- [ ] Run `bash server/scripts/test-with-postgres.sh`. Expected: all `ok`.
- [ ] Commit: `git commit -m "docs: document sessions and login limits"`.

## Out of scope
- **P4b:**
  - enrollment token;
  - public install.sh and checkin;
  - nginx `/api` proxy and `X-Forwarded-For`;
  - removing `VITE_API_URL`, `VITE_API_KEY` and CORS;
  - B10, B23.
- **P4c:**
  - AES-GCM for node keys;
  - hiding `wireguard_private_key`;
  - audit `user_id`.
- **Not planned in any P4 part:**
  - a last-user or self-delete guard (not in spec; the bootstrap user is re-created from env when the table is empty);
  - the `web/.env` file tracked by git. That is the user's call: `.env*` writes are denied to the agent.
