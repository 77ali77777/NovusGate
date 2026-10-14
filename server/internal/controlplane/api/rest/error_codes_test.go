package rest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var b struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("not an error body: %s", body)
	}
	return b.Error.Code
}

func TestErrorCodes(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	admin := &models.Network{Name: "contract-admin", CIDR: "10.98.0.0/24", ListenPort: 51898, InterfaceName: "wg0"}
	if err := st.CreateNetwork(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"bad body", "POST", "/api/v1/networks", `{`, 400, "invalid_request_body"},
		{"login", "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"nope"}`, 401, "invalid_credentials"},
		{"login unknown", "POST", "/api/v1/auth/login", `{"username":"ghost","password":"nope"}`, 401, "invalid_credentials"},
		{"old password", "PUT", "/api/v1/auth/password", `{"username":"contract-user","oldPassword":"nope","newPassword":"x1y2z3"}`, 401, "invalid_old_password"},
		{"overlap", "POST", "/api/v1/networks", `{"name":"contract-o","cidr":"10.66.0.0/25"}`, 409, "cidr_overlap"},
		{"admin network", "DELETE", "/api/v1/networks/" + admin.ID, "", 403, "admin_network_protected"},
		{"protected port", "POST", "/api/v1/firewall/host/port/close", `{"port":22,"protocol":"tcp"}`, 403, "protected_rule"},
		{"missing", "GET", "/api/v1/networks/00000000-0000-4000-8000-000000000000", "", 404, "not_found"},
	}
	for _, c := range cases {
		rec := callAs(t, s, c.method, c.path, c.body, true)
		if rec.Code != c.status || errorCode(t, rec.Body.Bytes()) != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, rec.Code, rec.Body, c.status, c.code)
		}
	}
}

func TestFirewallEngineErrorCodes(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeShadow)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`); rec.Code != 409 || errorCode(t, rec.Body.Bytes()) != "firewall_disabled" {
		t.Fatalf("shadow mode v2 change = %d %s", rec.Code, rec.Body)
	}
	s, _ = newEngineServer(t, firewall.ModeNft)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`); rec.Code != 200 {
		t.Fatalf("pending change = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9444}`); rec.Code != 409 || errorCode(t, rec.Body.Bytes()) != "firewall_change_pending" {
		t.Fatalf("second change while one is pending = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/confirm/no-such-id", ""); rec.Code != 410 || errorCode(t, rec.Body.Bytes()) != "firewall_change_expired" {
		t.Fatalf("confirm of an unknown change = %d %s", rec.Code, rec.Body)
	}

	// The lockout guard: a fresh engine (nothing pending) refuses to block the operator.
	s, _ = newEngineServer(t, firewall.ModeNft)
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", `{"ip":"198.51.100.200"}`); rec.Code != 400 || errorCode(t, rec.Body.Bytes()) != "firewall_rejected" {
		t.Fatalf("blocking the operator = %d %s", rec.Code, rec.Body)
	}
}
