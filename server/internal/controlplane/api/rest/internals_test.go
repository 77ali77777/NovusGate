package rest

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
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
