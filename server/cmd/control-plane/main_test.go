package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestMaskDatabaseURLHidesPassword(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://novus:s3cr3t@postgres:5432/novusgate?sslmode=disable": "postgres://novus:xxxxx@postgres:5432/novusgate?sslmode=disable",
		"host=postgres user=novus password=s3cr3t dbname=novusgate":       "host=postgres user=novus password=xxxxx dbname=novusgate",
		"postgres://postgres:5432/novusgate":                              "postgres://postgres:5432/novusgate",
	} {
		got := maskDatabaseURL(in)
		if got != want || strings.Contains(got, "s3cr3t") {
			t.Errorf("maskDatabaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Passwords that url.Parse cannot handle or that sit outside the userinfo
// must still never reach the logs.
func TestMaskDatabaseURLHidesUnusualPasswords(t *testing.T) {
	for _, in := range []string{
		"postgres://novus:p#ss/w@rd@postgres:5432/novusgate?sslmode=disable", // unencoded, as compose builds it
		"postgres://novus@postgres/novusgate?password=s3cr3t&sslmode=disable",
		"host=postgres user=novus password='s3cr3t with spaces' dbname=novusgate",
		"host=postgres user=novus password = s3cr3t dbname=novusgate",
	} {
		got := maskDatabaseURL(in)
		for _, secret := range []string{"s3cr3t", "p#ss", "w@rd", "spaces"} {
			if strings.Contains(got, secret) {
				t.Errorf("maskDatabaseURL(%q) = %q leaks %q", in, got, secret)
			}
		}
		if !strings.Contains(got, "xxxxx") {
			t.Errorf("maskDatabaseURL(%q) = %q, want the password replaced by xxxxx", in, got)
		}
	}
}

// net/http's own errors (accept failures, panics) must reach the log at
// Error, so LOG_LEVEL=warn does not hide them.
func TestHTTPServerLogsItsErrorsAtErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv := newHTTPServer(":0", http.NotFoundHandler(), logger)
	if srv.ErrorLog == nil {
		t.Fatal("http.Server.ErrorLog must be set")
	}
	srv.ErrorLog.Print("http: Accept error: too many open files")
	if !strings.Contains(buf.String(), `"level":"ERROR"`) || !strings.Contains(buf.String(), "Accept error") {
		t.Fatalf("server error not logged at ERROR: %q", buf.String())
	}
}
