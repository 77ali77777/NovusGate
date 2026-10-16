package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/reconciler"
	"github.com/novusgate/novusgate/internal/shared/version"
	"github.com/novusgate/novusgate/internal/wireguard"
)

type healthBody struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Checks  struct {
		Database struct {
			OK bool `json:"ok"`
		} `json:"database"`
		WireGuard struct {
			OK         bool              `json:"ok"`
			Interfaces map[string]string `json:"interfaces"`
		} `json:"wireguard"`
		Firewall struct {
			OK      bool   `json:"ok"`
			Mode    string `json:"mode"`
			Ready   *bool  `json:"ready"`
			Pending *bool  `json:"pending"`
		} `json:"firewall"`
	} `json:"checks"`
}

func getHealth(t *testing.T, s *Server) healthBody {
	t.Helper()
	rec := callAs(t, s, "GET", "/health", "", true)
	if rec.Code != 200 {
		t.Fatalf("/health = %d %s (it always answers 200)", rec.Code, rec.Body)
	}
	var h healthBody
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHealthReportsInterfaces(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	interfaceUp = func(name string) bool { return name == "wg66" }
	h := getHealth(t, s)
	if h.Version != version.Version || !h.Checks.Database.OK || h.Checks.Firewall.Mode != "iptables" || !h.Checks.Firewall.OK {
		t.Fatalf("health = %+v", h)
	}
	if h.Checks.WireGuard.OK || h.Checks.WireGuard.Interfaces["wg66"] != "up" || h.Checks.WireGuard.Interfaces["wg68"] != "down" || h.Status != "degraded" {
		t.Fatalf("a down interface makes the system degraded: %+v", h)
	}
	interfaceUp = func(string) bool { return true }
	if h := getHealth(t, s); h.Status != "healthy" || !h.Checks.WireGuard.OK {
		t.Fatalf("all up must be healthy: %+v", h)
	}
}

func TestHealthWhenDatabaseIsDown(t *testing.T) {
	s, st, _ := newContractServer(t)
	st.Close()
	h := getHealth(t, s)
	if h.Status != "degraded" || h.Checks.Database.OK {
		t.Fatalf("a closed database must be reported, not hidden: %+v", h)
	}
}

func TestHealthReportsFirewallEngine(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeNft)
	origUp := interfaceUp
	interfaceUp = func(string) bool { return true }
	t.Cleanup(func() { interfaceUp = origUp })
	h := getHealth(t, s)
	if h.Checks.Firewall.Mode != "nft" || h.Checks.Firewall.Ready == nil || !*h.Checks.Firewall.Ready ||
		h.Checks.Firewall.Pending == nil || *h.Checks.Firewall.Pending || !h.Checks.Firewall.OK {
		t.Fatalf("ready nft engine: %+v", h.Checks.Firewall)
	}
	old := s.firewall
	s.SetFirewall(&firewall.Engine{Mode: firewall.ModeNft, Store: old.Store, Applier: old.Applier, Now: old.Now, Detect: old.Detect})
	if h := getHealth(t, s); h.Checks.Firewall.OK || h.Status != "degraded" {
		t.Fatalf("an engine that is not ready is degraded: %+v", h)
	}
}

func TestHealthReportsReconciler(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	rec := reconciler.New(reconciler.ModeShadow, st, func(string) reconciler.PeerControl { return brokenPeers{} })
	s.SetReconciler(rec)
	rec.RunOnce(context.Background())
	var body struct {
		Status string `json:"status"`
		Checks struct {
			Reconciler struct {
				OK      bool   `json:"ok"`
				Mode    string `json:"mode"`
				LastRun string `json:"last_run"`
				Pending int    `json:"pending"`
			} `json:"reconciler"`
		} `json:"checks"`
	}
	r := callAs(t, s, "GET", "/health", "", true)
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Checks.Reconciler.Mode != "shadow" || body.Checks.Reconciler.OK || body.Checks.Reconciler.LastRun == "" || body.Status != "degraded" {
		t.Fatalf("a reconciler that cannot read interfaces is degraded: %+v", body)
	}
}

// brokenPeers fails like an interface that is down.
type brokenPeers struct{}

func (brokenPeers) GetPeers() (map[string]wireguard.PeerStatus, error) {
	return nil, fmt.Errorf("Unable to access interface")
}
func (brokenPeers) AddPeer(string, string) error              { return nil }
func (brokenPeers) UpdatePeerAllowedIPs(string, string) error { return nil }
func (brokenPeers) RemovePeer(string) error                   { return nil }

// TestContractHealthBranches freezes the health keys whose present value is
// null or false: a reconciler that has not run yet and an nft engine that
// is not ready.
func TestContractHealthBranches(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	s.SetReconciler(reconciler.New(reconciler.ModeShadow, st, func(string) reconciler.PeerControl { return brokenPeers{} }))
	es, _ := newEngineServer(t, firewall.ModeNft)
	old := es.firewall
	s.SetFirewall(&firewall.Engine{Mode: firewall.ModeNft, Store: old.Store, Applier: old.Applier, Now: old.Now, Detect: old.Detect})
	rec := callAs(t, s, "GET", "/health", "", true)
	assertContract(t, "health_idle_reconciler_nft_not_ready", rec)
	assertMatchesSpec(t, s, "GET", "/health", rec)
}

// /health is public, but only callers with a panel session or the API key
// see the component checks; others get the status and version.
func TestHealthDetailsNeedAuth(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	interfaceUp = func(name string) bool { return name == "wg66" } // degraded

	keys := func(rec interface{ Bytes() []byte }) map[string]json.RawMessage {
		t.Helper()
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rec.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	anon := callAs(t, s, "GET", "/health", "", false)
	m := keys(anon.Body)
	if anon.Code != 200 || len(m) != 2 || string(m["status"]) != `"degraded"` || string(m["version"]) != `"`+version.Version+`"` {
		t.Fatalf("anonymous /health = %d %s, want only status (still degraded) and version", anon.Code, anon.Body)
	}

	orig := apiKey
	apiKey = "health-test-key"
	defer func() { apiKey = orig }()
	for key, want := range map[string]bool{"health-test-key": true, "wrong-key": false} {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		if _, got := keys(rec.Body)["checks"]; got != want {
			t.Errorf("X-API-Key %q: checks shown = %v, want %v", key, got, want)
		}
	}
}
