package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func clearRows(t *testing.T, query string) {
	t.Helper()
	db, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func clearTable(t *testing.T, table string) {
	t.Helper()
	db, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("DELETE FROM " + table); err != nil {
		t.Fatal(err)
	}
}

// Every successful change through the API and every login attempt lands in
// the audit log with the route, status, user and address; reads, failed
// changes and node check-ins do not.
func TestAuditLogRecordsChanges(t *testing.T) {
	s, _, _ := newContractServer(t)
	clearTable(t, "firewall_audit_log")

	callAs(t, s, "GET", "/api/v1/networks", "", true)
	callAs(t, s, "POST", "/api/v1/networks", `{`, true) // 400: not recorded
	if rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"audit-net","cidr":"10.81.0.0/24"}`, true); rec.Code != 201 {
		t.Fatalf("create network = %d %s", rec.Code, rec.Body)
	}
	callAs(t, s, "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"wrong"}`, false)

	rec := callAs(t, s, "GET", "/api/v1/audit?limit=10", "", true)
	if rec.Code != 200 {
		t.Fatalf("audit = %d %s", rec.Code, rec.Body)
	}
	var got AuditLogResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Entries) != 2 {
		t.Fatalf("entries = %s", rec.Body)
	}
	login, create := got.Entries[0], got.Entries[1] // newest first
	if login.Action != "POST /api/v1/auth/login" || login.Details["status"] != float64(401) || login.UserIP == "" {
		t.Fatalf("login entry = %+v", login)
	}
	// A login entry says which account was tried (there is no session yet).
	if login.Details["username"] != "contract-user" {
		t.Fatalf("login entry details = %+v, want the tried username", login.Details)
	}
	if create.Action != "POST /api/v1/networks" || create.Username != "contract-user" || create.Details["status"] != float64(201) {
		t.Fatalf("create entry = %+v", create)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/audit", rec)

	// older page
	older := callAs(t, s, "GET", "/api/v1/audit?limit=10&before="+login.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), "", true)
	if !strings.Contains(older.Body.String(), "POST /api/v1/networks") || strings.Contains(older.Body.String(), "auth/login") {
		t.Fatalf("before = %s", older.Body)
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	s, st, _ := newContractServer(t)
	other := testSession(t, st, "contract-user") // a second session of the same user
	_ = other
	rec := callAs(t, s, "GET", "/api/v1/auth/sessions", "", true)
	if rec.Code != 200 {
		t.Fatalf("sessions = %d %s", rec.Code, rec.Body)
	}
	var got SessionsResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	current := 0
	var otherID string
	for _, sess := range got.Sessions {
		if sess.Current {
			current++
		} else if sess.Username == "contract-user" {
			otherID = sess.ID
		}
	}
	if current != 1 || otherID == "" || strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("sessions = %s", rec.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/auth/sessions", rec)

	if rec := callAs(t, s, "DELETE", "/api/v1/auth/sessions/"+otherID, "", true); rec.Code != 204 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	// the revoked token no longer works
	saved := adminToken
	adminToken = other
	if rec := callAs(t, s, "GET", "/api/v1/networks", "", true); rec.Code != 401 {
		t.Fatalf("revoked token = %d", rec.Code)
	}
	adminToken = saved
	if rec := callAs(t, s, "DELETE", "/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000", "", true); rec.Code != 404 {
		t.Fatalf("unknown session = %d", rec.Code)
	}
	if rec := callAs(t, s, "DELETE", "/api/v1/auth/sessions/nope", "", true); rec.Code != 404 {
		t.Fatalf("bad id = %d", rec.Code)
	}
	_ = context.Background()
}

// A rate-limited login (429) is not recorded: it costs the caller nothing
// (no password check), so recording it let anyone grow the table.
func TestRateLimitedLoginsAreNotAudited(t *testing.T) {
	s, _, _ := newContractServer(t)
	clearTable(t, "firewall_audit_log")
	orig := loginLimit
	t.Cleanup(func() { loginLimit = orig })
	loginLimit = newLoginLimiter(1, 15*time.Minute)
	bad := `{"username":"contract-user","password":"wrong"}`
	callAs(t, s, "POST", "/api/v1/auth/login", bad, false)
	for i := 0; i < 3; i++ {
		if rec := callAs(t, s, "POST", "/api/v1/auth/login", bad, false); rec.Code != 429 {
			t.Fatalf("attempt %d = %d, want 429", i, rec.Code)
		}
	}
	var got AuditLogResponse
	json.Unmarshal(callAs(t, s, "GET", "/api/v1/audit?limit=10", "", true).Body.Bytes(), &got)
	if len(got.Entries) != 1 || got.Entries[0].Details["status"] != float64(401) {
		t.Fatalf("audit = %+v, want the 401 only", got.Entries)
	}
}
