package rest

import (
	"context"
	"encoding/json"
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
