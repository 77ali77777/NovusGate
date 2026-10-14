package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
	"golang.org/x/crypto/bcrypt"
)

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
		hash, err := bcrypt.GenerateFromPassword([]byte("contract-pw-1"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
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

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %d %s: %v", rec.Code, rec.Body, err)
	}
}

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
	if rec.Code != http.StatusUnauthorized || errorCode(t, rec.Body.Bytes()) != "invalid_token" {
		t.Fatalf("expired session = %d %s, want 401 invalid_token", rec.Code, rec.Body)
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

func TestLoginRateLimit(t *testing.T) {
	s, _, _ := newContractServer(t)
	orig := loginLimit
	t.Cleanup(func() { loginLimit = orig })
	loginLimit = newLoginLimiter(3, 15*time.Minute)
	good := `{"username":"contract-user","password":"contract-pw-1"}`
	bad := `{"username":"contract-user","password":"wrong"}`
	if rec := callAs(t, s, "POST", "/api/v1/auth/login", bad, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first bad = %d", rec.Code)
	}
	if rec := callAs(t, s, "POST", "/api/v1/auth/login", good, false); rec.Code != http.StatusOK {
		t.Fatalf("a good login under the limit = %d", rec.Code)
	}
	for i := 0; i < 3; i++ {
		callAs(t, s, "POST", "/api/v1/auth/login", bad, false)
	}
	rec := callAs(t, s, "POST", "/api/v1/auth/login", good, false)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit = %d %v, want 429 with Retry-After", rec.Code, rec.Header())
	}
	if code := errorCode(t, rec.Body.Bytes()); code != "too_many_attempts" {
		t.Fatalf("code = %q", code)
	}
}

func TestPasswordChangeIsForSessionUser(t *testing.T) {
	s, st, _ := newContractServer(t)
	mine := adminToken
	testSession(t, st, "contract-other") // a second account
	adminToken = mine
	body := `{"username":"contract-other","oldPassword":"contract-pw-1","newPassword":"x-new-pw"}`
	rec := callAs(t, s, "PUT", "/api/v1/auth/password", body, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("changing another account = %d %s, want 403", rec.Code, rec.Body)
	}
}

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	s, st, _ := newContractServer(t)
	mine := adminToken
	other := testSession(t, st, "contract-user") // a second session of the same user
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
	mine := adminToken
	victim := testSession(t, st, "contract-gone")
	adminToken = mine
	u, err := st.GetUserByUsername(context.Background(), "contract-gone")
	if err != nil || u == nil {
		t.Fatalf("user = %v, %v", u, err)
	}
	if rec := callAs(t, s, "DELETE", "/api/v1/users/"+u.ID, "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	adminToken = victim
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user's session = %d, want 401", rec.Code)
	}
}

// Concurrent failures must not slip past the limit while bcrypt runs.
func TestLoginRateLimitHoldsUnderConcurrency(t *testing.T) {
	s, _, _ := newContractServer(t)
	loginLimit = newLoginLimiter(3, 15*time.Minute) // newContractServer restores it
	bad := `{"username":"contract-user","password":"wrong"}`
	const n = 20
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(bad))
			req.RemoteAddr = "198.51.100.201:5555"
			rec := httptest.NewRecorder()
			s.router.ServeHTTP(rec, req)
			codes <- rec.Code
		}()
	}
	wg.Wait()
	close(codes)
	evaluated := 0
	for c := range codes {
		if c == http.StatusUnauthorized {
			evaluated++
		}
	}
	if evaluated > 3 {
		t.Fatalf("%d passwords were checked concurrently, want at most 3", evaluated)
	}
}

func TestClientIPTrustsOnlyLoopbackProxy(t *testing.T) {
	for _, c := range []struct{ remote, want string }{
		{"127.0.0.1:40000", "203.0.113.5"},     // the panel's nginx
		{"[::1]:40000", "203.0.113.5"},         // the panel's nginx over IPv6
		{"198.51.100.9:40000", "198.51.100.9"}, // anyone else cannot choose their IP
	} {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = c.remote
		req.Header.Set("X-Real-IP", "203.0.113.5")
		if got := clientIP(req); got != c.want {
			t.Errorf("clientIP(%s) = %s, want %s", c.remote, got, c.want)
		}
	}
}

// The panel calls the API through its own nginx, so no CORS headers are sent.
func TestNoCORSHeaders(t *testing.T) {
	s, _, _ := newContractServer(t)
	rec := callAs(t, s, "GET", "/api/v1/networks", "", true)
	if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want none", v)
	}
}

// Handlers reached without a session (or whose user vanished) answer 401.
func TestAuthHandlersWithoutSessionUser(t *testing.T) {
	s, _, _ := newContractServer(t)
	ghost := &models.User{ID: "00000000-0000-4000-8000-000000000001", Username: "ghost"}
	for name, h := range map[string]http.HandlerFunc{"password": s.handleUpdatePassword, "logout": s.handleLogout} {
		for _, ctx := range []context.Context{context.Background(), context.WithValue(context.Background(), sessionKey{}, session{ghost, "h"})} {
			req := httptest.NewRequest("PUT", "/x", strings.NewReader(`{"oldPassword":"a","newPassword":"b"}`)).WithContext(ctx)
			rec := httptest.NewRecorder()
			h(rec, req)
			if name == "logout" && ctx != context.Background() {
				continue // a vanished user's logout just deletes nothing
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s without a session user = %d %s, want 401", name, rec.Code, rec.Body)
			}
		}
	}
}

// A success only removes its own attempt; earlier failures still count.
func TestSuccessfulLoginKeepsFailures(t *testing.T) {
	s, _, _ := newContractServer(t)
	loginLimit = newLoginLimiter(3, 15*time.Minute) // newContractServer restores it
	good := `{"username":"contract-user","password":"contract-pw-1"}`
	bad := `{"username":"contract-user","password":"wrong"}`
	for _, body := range []string{bad, bad, good, bad} {
		callAs(t, s, "POST", "/api/v1/auth/login", body, false)
	}
	if rec := callAs(t, s, "POST", "/api/v1/auth/login", good, false); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after 3 failures and a success in between = %d, want 429", rec.Code)
	}
}

func TestLimiterKeysIPv6By64AndPrunes(t *testing.T) {
	l := newLoginLimiter(2, time.Minute)
	now := time.Now()
	l.begin(limiterKey("2001:db8:1:2::5"), now)
	l.begin(limiterKey("2001:db8:1:2::9"), now)
	if _, ok := l.begin(limiterKey("2001:db8:1:2:ffff::1"), now); ok {
		t.Fatal("addresses in one /64 share a counter")
	}
	if limiterKey("198.51.100.7") != "198.51.100.7" {
		t.Fatal("IPv4 keys are the address")
	}
	for i := 0; i < maxTrackedIPs+50; i++ {
		l.begin(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), now)
	}
	if n := len(l.fails); n > maxTrackedIPs {
		t.Fatalf("tracked = %d, want at most %d", n, maxTrackedIPs)
	}
}

// Unknown usernames still run bcrypt, so they answer as slowly as known ones.
func TestUnknownUserRunsBcrypt(t *testing.T) {
	s, _, _ := newContractServer(t)
	orig := comparePassword
	t.Cleanup(func() { comparePassword = orig })
	calls := 0
	comparePassword = func(hash, pw []byte) error { calls++; return orig(hash, pw) }
	callAs(t, s, "POST", "/api/v1/auth/login", `{"username":"nobody-here","password":"x"}`, false)
	if calls != 1 {
		t.Fatalf("bcrypt calls for an unknown user = %d, want 1", calls)
	}
}

// The API key ends up in an nginx config: only characters that cannot
// break it out of its quotes are allowed.
func TestValidateAPIKey(t *testing.T) {
	for key, ok := range map[string]bool{"": true, "a1B2-c3_d4.e~": true, "novusgate_secret_key": true, `bad"key`: false, "bad$key": false, "bad key": false} {
		if err := ValidateAPIKey(key); (err == nil) != ok {
			t.Errorf("ValidateAPIKey(%q) = %v, want ok=%v", key, err, ok)
		}
	}
}
