package rest

import (
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A fail2ban log that exists but cannot be read is reported, not shown as
// an empty history.
func TestFail2BanHistoryReportsReadErrors(t *testing.T) {
	s, _, _ := newContractServer(t)
	openFail2BanLog = func() (io.ReadCloser, error) { return nil, fs.ErrPermission }
	rec := callAs(t, s, "GET", "/api/v1/system/fail2ban/ban-history", "", true)
	var body Fail2BanHistoryResponse
	decodeJSON(t, rec, &body)
	if rec.Code != http.StatusOK || body.Error == "" || len(body.History) != 0 {
		t.Fatalf("unreadable log = %d %+v, want 200 with an error field", rec.Code, body)
	}
	openFail2BanLog = func() (io.ReadCloser, error) { return nil, errors.Join(fs.ErrNotExist) }
	rec = callAs(t, s, "GET", "/api/v1/system/fail2ban/ban-history", "", true)
	body = Fail2BanHistoryResponse{}
	decodeJSON(t, rec, &body)
	if body.Error != "" {
		t.Fatalf("a missing log is just no history yet, got error %q", body.Error)
	}
}

func TestIgnoreIPListKeepsDotlessHostnames(t *testing.T) {
	got := parseIgnoreIPList("These IP addresses/networks are ignored:\n|- 127.0.0.1/8\n|- ::1\n|- localhost\n|- my-host.example\n`- 10.0.0.1\n")
	want := map[string]bool{"127.0.0.1/8": true, "::1": true, "localhost": true, "my-host.example": true, "10.0.0.1": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected %q in %v", g, got)
		}
	}
}

// A network needs room for the hub and at least one peer.
func TestCreateNetworkRejectsTooSmallCIDR(t *testing.T) {
	s, _, _ := newContractServer(t)
	for _, cidr := range []string{"10.81.0.0/31", "10.81.0.1/32"} {
		rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"contract-tiny","cidr":"`+cidr+`"}`, true)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec.Body.Bytes()) != "invalid_cidr" {
			t.Errorf("%s = %d %s, want 400 invalid_cidr", cidr, rec.Code, rec.Body)
		}
	}
}

// A panic after the handler started writing must not append an error body
// to the partial response.
func TestRecoverAfterPartialWrite(t *testing.T) {
	captureLogs(t)
	h := RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		panic("late failure")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "partial" {
		t.Fatalf("got %d %q, want the partial 200 body only", rec.Code, rec.Body)
	}
}

func TestCaptureLogsRestoresLogOutput(t *testing.T) {
	before := log.Writer()
	t.Run("capture", func(t *testing.T) { captureLogs(t) })
	if log.Writer() != before {
		t.Fatal("captureLogs must restore the standard logger's output")
	}
}

func TestLooksLikeTestDatabase(t *testing.T) {
	for url, ok := range map[string]bool{
		"postgres://ng:ng@novusgate-test-pg:5432/ng?sslmode=disable": true,
		"postgres://u:p@localhost:5432/novusgate_test":               true,
		"postgres://u:p@db.prod.example:5432/novusgate":              false,
	} {
		if got := looksLikeTestDatabase(url); got != ok {
			t.Errorf("looksLikeTestDatabase(%q) = %v, want %v", url, got, ok)
		}
	}
}

func TestNormalizeBodyNumbersIDsAndKeepsEmbeddedTimes(t *testing.T) {
	a, b := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	got := normalizeBody(`{"id":"` + a + `","network_id":"` + b + `","owner":"` + a + `","at":"2026-10-14T12:00:00Z","message":"use e.g. 2026-10-14T12:00:00Z"}`)
	want := `{"id":"<uuid-1>","network_id":"<uuid-2>","owner":"<uuid-1>","at":"<time>","message":"use e.g. 2026-10-14T12:00:00Z"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
