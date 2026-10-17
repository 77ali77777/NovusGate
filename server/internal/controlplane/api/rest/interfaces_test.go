package rest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// A bring-up that keeps failing is not retried every 30 s (each failed
// wg-quick may leave PostUp firewall rules behind): it backs off.
func TestKeepInterfacesBacksOff(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	origNow := ifaceNow
	ifaceNow = func() time.Time { return now }
	t.Cleanup(func() { ifaceNow = origNow })
	calls := fakeInterfaces(t, map[string]bool{"wg68": true}, errors.New("start failed"))
	s.keepInterfacesOnce(context.Background())
	s.keepInterfacesOnce(context.Background())
	if len(*calls) != 1 {
		t.Fatalf("a second try right away = %d bring-ups, want 1", len(*calls))
	}
	now = now.Add(5 * time.Minute)
	s.keepInterfacesOnce(context.Background())
	if len(*calls) != 2 {
		t.Fatalf("after the back-off = %d bring-ups, want 2", len(*calls))
	}
}

// The check never brings back a network that is gone (deleted meanwhile).
func TestKeepInterfaceSkipsADeletedNetwork(t *testing.T) {
	s, _, _ := newContractServer(t)
	calls := fakeInterfaces(t, map[string]bool{}, nil)
	s.keepInterface(context.Background(), "00000000-0000-0000-0000-0000000000aa")
	if len(*calls) != 0 {
		t.Fatalf("a deleted network was brought up: %+v", *calls)
	}
}

// Deleting a network waits for a bring-up of its interface in progress, so
// a check cannot start the unit again after the delete stopped it.
func TestDeleteNetworkWaitsForTheInterface(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	fakeInterfaces(t, map[string]bool{}, nil)
	origTeardown := wgTeardown
	wgTeardown = func(string) {}
	t.Cleanup(func() { wgTeardown = origTeardown })
	unlock := s.lockInterface("wg66")
	done := make(chan int)
	go func() { done <- callAs(t, s, "DELETE", "/api/v1/networks/"+seed.network.ID, "", true).Code }()
	select {
	case <-done:
		t.Fatal("the delete must wait for the interface lock")
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	if code := <-done; code != 204 {
		t.Fatalf("delete = %d", code)
	}
}

// Viewers see whether an interface runs, not the host's error text.
func TestViewerSeesStateNotReason(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	fakeInterfaces(t, map[string]bool{}, nil)
	s.setInterfaceError(seed.network.ID, "journal: secret-ish host detail")
	viewer := roleSession(t, st, "contract-iface-viewer", "viewer")
	body := callWith(t, s, viewer, "GET", "/api/v1/networks/"+seed.network.ID, "").Body.String()
	if !strings.Contains(body, `"interface_up":false`) || strings.Contains(body, "host detail") {
		t.Fatalf("viewer = %s", body)
	}
	if body := callAs(t, s, "GET", "/api/v1/networks/"+seed.network.ID, "", true).Body.String(); !strings.Contains(body, "host detail") {
		t.Fatalf("an admin sees the reason: %s", body)
	}
}

// Restarting wg-quick@wgN from the Server page drops its runtime peers; they
// are put back right away.
func TestServerPageRestartOfAWireGuardUnitRestoresPeers(t *testing.T) {
	s, h := newServerAdmin(t)
	seed := seedContract(t, s.store)
	fakeInterfaces(t, map[string]bool{"wg66": true}, nil)
	var restored []string
	restoreNetworkPeers = func(_ *Server, _ context.Context, n *models.Network, _ *wireguard.Manager) {
		restored = append(restored, n.InterfaceName)
	}
	h.out["systemctl list-units wg-quick@* --all --no-legend --plain"] = "wg-quick@wg66.service loaded active exited WireGuard\n"
	callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"contract-pw-1"}`, true)
	rec := callAs(t, s, "POST", "/api/v1/server/services/wg-quick@wg66/restart", "", true)
	if rec.Code != 204 || len(restored) != 1 || restored[0] != "wg66" {
		t.Fatalf("restart = %d %s, restored %v (network %s)", rec.Code, rec.Body, restored, seed.network.ID)
	}
}
