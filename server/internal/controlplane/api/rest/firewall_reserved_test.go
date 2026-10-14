package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Spec §6b.4: an allow rule never opens the VPN-only admin and API ports.
func TestValidateIPRuleRejectsReservedAllowPorts(t *testing.T) {
	now := time.Now()
	for _, ports := range []string{"3007", "80,5432", "8000-8100", "8443:9000"} {
		if _, err := validateIPRule(v2IPRuleRequest{Action: "allow", Prefix: "203.0.113.5", Ports: ports}, "panel", now); err == nil {
			t.Errorf("allow on ports %q must be rejected", ports)
		}
	}
	ok := []v2IPRuleRequest{
		{Action: "allow", Prefix: "203.0.113.5"},                                 // whole address: the guard keeps admin ports closed
		{Action: "allow", Prefix: "203.0.113.5", Ports: "80,443"},                // ordinary ports
		{Action: "allow", Prefix: "203.0.113.5", Protocol: "udp", Ports: "5432"}, // reserved ports are TCP
		{Action: "block", Prefix: "203.0.113.5", Ports: "8080"},                  // blocking is always allowed
	}
	for _, req := range ok {
		if _, err := validateIPRule(req, "panel", now); err != nil {
			t.Errorf("%+v: unexpected error %v", req, err)
		}
	}
}

func TestAllowIPIptablesRejectsReservedPorts(t *testing.T) {
	ran := false
	orig := execHostCommand
	execHostCommand = func(string, ...string) (string, error) { ran = true; return "", nil }
	defer func() { execHostCommand = orig }()

	s := &Server{} // no engine: legacy iptables mode
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/host/ip/allow",
		strings.NewReader(`{"ip":"203.0.113.5","ports":"22,8080"}`))
	rec := httptest.NewRecorder()
	s.handleFirewallAllowIP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	if ran {
		t.Fatal("no iptables command may run for a rejected request")
	}
}
