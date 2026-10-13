package rest

import (
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/wireguard"
)

// SetupInterface already brings the interface up; a second Up always fails
// with "already exists" and logged a false error for every new network.
func TestCreateNetworkBringsTheInterfaceUpOnce(t *testing.T) {
	logs := captureLogs(t)
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	created := []string{}
	wgInit = func(*wireguard.Manager) error { return nil } // pretend wg is installed
	wgCreateInterface = func(m *wireguard.Manager, _, addr string, _ int) error {
		created = append(created, m.InterfaceName+" "+addr)
		return nil
	}
	if rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"contract-up","cidr":"10.76.0.0/24"}`, true); rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if len(created) != 1 || !strings.HasSuffix(created[0], " 10.76.0.1/24") {
		t.Fatalf("interface setup calls = %v", created)
	}
	if strings.Contains(logs.String(), "Failed to bring up") {
		t.Fatalf("no second Up may run:\n%s", logs.String())
	}
}
