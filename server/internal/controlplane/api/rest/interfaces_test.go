package rest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// A network whose interface did not come up said "Active" and nothing
// else (the reason only went to the log). Its JSON now carries whether the
// interface runs and the last reason it did not; a dead interface is
// brought back by a check every 30 s, and by hand with POST .../restart.

type bringUpCall struct {
	iface   string
	restart bool
}

// fakeInterfaces makes WireGuard "available" and records bring-ups; up says
// which interfaces exist; fail is the error a bring-up returns.
func fakeInterfaces(t *testing.T, up map[string]bool, fail error) *[]bringUpCall {
	t.Helper()
	calls := &[]bringUpCall{}
	origInit, origUp, origBring, origRestore := wgInit, interfaceUp, wgBringUp, restoreNetworkPeers
	wgInit = func(*wireguard.Manager) error { return nil }
	interfaceUp = func(name string) bool { return up[name] }
	wgBringUp = func(m *wireguard.Manager, restart bool) error {
		*calls = append(*calls, bringUpCall{m.InterfaceName, restart})
		if fail == nil {
			up[m.InterfaceName] = true
		}
		return fail
	}
	restoreNetworkPeers = func(*Server, context.Context, *models.Network, *wireguard.Manager) {}
	t.Cleanup(func() { wgInit, interfaceUp, wgBringUp, restoreNetworkPeers = origInit, origUp, origBring, origRestore })
	return calls
}

func TestNetworkShowsInterfaceStatus(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	up := map[string]bool{}
	fakeInterfaces(t, up, nil)
	path := "/api/v1/networks/" + seed.network.ID

	s.setInterfaceError(seed.network.ID, "systemctl start wg-quick@wg66 failed: no route")
	body := callAs(t, s, "GET", path, "", true).Body.String()
	if !strings.Contains(body, `"interface_up":false`) || !strings.Contains(body, `"interface_error":"systemctl start wg-quick@wg66 failed: no route"`) {
		t.Fatalf("down network = %s", body)
	}
	up["wg66"] = true
	s.setInterfaceError(seed.network.ID, "")
	body = callAs(t, s, "GET", "/api/v1/networks", "", true).Body.String()
	if !strings.Contains(body, `"interface_up":true`) {
		t.Fatalf("list = %s", body)
	}
}

// Creating a network whose interface fails still stores it (201), and says
// so: the panel shows the reason and a restart button.
func TestCreateNetworkReportsInterfaceFailure(t *testing.T) {
	s, _, _ := newContractServer(t)
	fakeInterfaces(t, map[string]bool{}, nil)
	orig := wgCreateInterface
	wgCreateInterface = func(*wireguard.Manager, string, string, int) error {
		return errors.New("systemctl start wg-quick@wg1 failed: AppArmor")
	}
	t.Cleanup(func() { wgCreateInterface = orig })
	rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"contract-iface","cidr":"10.29.0.0/24"}`, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"interface_up":false`) ||
		!strings.Contains(rec.Body.String(), "AppArmor") {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
}

func TestRestartInterface(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	up := map[string]bool{}
	calls := fakeInterfaces(t, up, nil)
	path := "/api/v1/networks/" + seed.network.ID + "/restart"
	s.setInterfaceError(seed.network.ID, "old failure")

	rec := callAs(t, s, "POST", path, "", true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"interface_up":true`) || strings.Contains(rec.Body.String(), "old failure") {
		t.Fatalf("restart = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "POST", path, rec)
	if len(*calls) != 1 || (*calls)[0] != (bringUpCall{"wg66", true}) {
		t.Fatalf("bring-ups = %+v", *calls)
	}

	failing := fakeInterfaces(t, map[string]bool{}, errors.New("systemctl restart wg-quick@wg66 failed: busy"))
	rec = callAs(t, s, "POST", path, "", true)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "interface_failed") || !strings.Contains(rec.Body.String(), "busy") {
		t.Fatalf("failed restart = %d %s", rec.Code, rec.Body)
	}
	if len(*failing) != 1 {
		t.Fatal("the restart must have been tried")
	}
	if rec := callAs(t, s, "POST", "/api/v1/networks/00000000-0000-0000-0000-000000000000/restart", "", true); rec.Code != 404 {
		t.Fatalf("unknown network = %d", rec.Code)
	}
}

// The check brings a missing interface back (and its peers), leaves a
// running one alone, and keeps the reason when it cannot.
func TestKeepInterfaces(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	up := map[string]bool{"wg68": true}
	calls := fakeInterfaces(t, up, nil)
	s.keepInterfacesOnce(context.Background())
	if len(*calls) != 1 || (*calls)[0] != (bringUpCall{"wg66", false}) {
		t.Fatalf("bring-ups = %+v (only the missing wg66)", *calls)
	}
	if !up["wg66"] {
		t.Fatal("wg66 must be up now")
	}

	up = map[string]bool{"wg68": true}
	fakeInterfaces(t, up, errors.New("start failed: no device"))
	s.keepInterfacesOnce(context.Background())
	body := callAs(t, s, "GET", "/api/v1/networks/"+seed.network.ID, "", true).Body.String()
	if !strings.Contains(body, "start failed: no device") {
		t.Fatalf("the reason must be kept: %s", body)
	}
}
