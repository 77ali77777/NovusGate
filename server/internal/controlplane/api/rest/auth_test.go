package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
