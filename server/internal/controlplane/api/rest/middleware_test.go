package rest

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// captureLogs routes slog to a buffer for one test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return &buf
}

func TestRequestLogNeverContainsSecrets(t *testing.T) {
	logs := captureLogs(t)
	s, _, _ := newContractServer(t)
	seedContract(t, s.store)
	req := httptest.NewRequest("POST", "/api/v1/auth/login?token=query-secret&password=query-pw",
		strings.NewReader(`{"username":"contract-user","password":"contract-pw-1"}`))
	req.Header.Set("Authorization", "Bearer header-secret")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	out := logs.String()
	for _, secret := range []string{"query-secret", "query-pw", "header-secret", "contract-pw-1", adminToken} {
		if strings.Contains(out, secret) {
			t.Fatalf("log leaks %q:\n%s", secret, out)
		}
	}
	if strings.Count(out, `"msg":"http request"`) != 1 ||
		!strings.Contains(out, `"method":"POST"`) || !strings.Contains(out, `"path":"/api/v1/auth/login"`) ||
		!strings.Contains(out, `"status":200`) {
		t.Fatalf("want exactly one request line with method, path and status:\n%s", out)
	}
}

func TestRecoverMiddleware(t *testing.T) {
	logs := captureLogs(t)
	r := mux.NewRouter()
	r.Use(LoggingMiddleware, RecoverMiddleware)
	r.HandleFunc("/boom", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
	r.HandleFunc("/abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))
	if rec.Code != 500 || strings.TrimSpace(rec.Body.String()) != `{"error":{"code":"internal_error","message":"internal server error"}}` {
		t.Fatalf("panic must become a 500 JSON error, got %d %s", rec.Code, rec.Body)
	}
	out := logs.String()
	if !strings.Contains(out, `"msg":"panic in handler"`) || !strings.Contains(out, "kaboom") ||
		!strings.Contains(out, "goroutine") || !strings.Contains(out, `"status":500`) {
		t.Fatalf("panic must be logged with its stack and the request line with 500:\n%s", out)
	}

	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("http.ErrAbortHandler must be re-panicked for net/http, got %v", v)
		}
	}()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/abort", nil))
}
