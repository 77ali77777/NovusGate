package rest

import (
	"net/http"
	"testing"
)

func TestAPIFallbacks(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)

	rec := callAs(t, s, "GET", "/api/v1/no-such-thing", "", true)
	if rec.Code != http.StatusNotFound || errorCode(t, rec.Body.Bytes()) != "not_found" {
		t.Fatalf("unknown /api path = %d %s", rec.Code, rec.Body)
	}
	rec = callAs(t, s, "DELETE", "/api/v1/stats/overview", "", true)
	if rec.Code != http.StatusMethodNotAllowed || errorCode(t, rec.Body.Bytes()) != "method_not_allowed" || rec.Header().Get("Allow") != "GET" {
		t.Fatalf("wrong method = %d %s Allow=%q", rec.Code, rec.Body, rec.Header().Get("Allow"))
	}
	rec = callAs(t, s, "PUT", "/api/v1/networks", "", true)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("wrong method on a two-method path = %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
	// Without a token the auth middleware still answers first.
	if rec := callAs(t, s, "GET", "/api/v1/no-such-thing", "", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated unknown path = %d", rec.Code)
	}
	// Real routes and the SPA are untouched.
	if rec := callAs(t, s, "GET", "/health", "", false); rec.Code != 200 {
		t.Fatalf("/health = %d", rec.Code)
	}
	if rec := callAs(t, s, "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"contract-pw-1"}`, false); rec.Code != 200 {
		t.Fatalf("login = %d", rec.Code)
	}
	if rec := callAs(t, s, "GET", "/", "", true); rec.Header().Get("Content-Type") == "application/json" {
		t.Fatalf("/ must still be served by the SPA handler, got JSON %s", rec.Body)
	}
}
