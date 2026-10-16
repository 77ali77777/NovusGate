package rest

import (
	"context"
	"database/sql"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// egressSetRe finds the internet exit set in a compiled ruleset.
var egressSetRe = regexp.MustCompile(`set egress_v4 \{[^}]*\}`)

func egressSet(script string) string { return egressSetRe.FindString(script) }

// tunnelNetwork creates a network with two nodes (10.24.0.5, 10.24.0.6).
func tunnelNetwork(t *testing.T, s *Server, iface string, port int) (*models.Network, *models.Node, *models.Node) {
	t.Helper()
	ctx := context.Background()
	if old, _ := s.store.GetNetworkByName(ctx, "contract-tunnel-"+iface); old != nil {
		s.store.DeleteNetwork(ctx, old.ID)
	}
	key := func(c string) string { return strings.Repeat(c, 43) + "=" }
	nw := &models.Network{Name: "contract-tunnel-" + iface, CIDR: "10.24.0.0/24", ServerPrivateKey: key("t"),
		ServerPublicKey: key("T"), ServerEndpoint: "203.0.113.1", InterfaceName: iface, ListenPort: port}
	if err := s.store.CreateNetwork(ctx, nw); err != nil {
		t.Fatal(err)
	}
	mk := func(name, ip, k string) *models.Node {
		n := &models.Node{NetworkID: nw.ID, Name: name, VirtualIP: net.ParseIP(ip), PublicKey: key(k),
			Labels: map[string]string{}, Status: models.NodeStatusOnline}
		if err := s.store.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
		if err := s.store.SetNodePrivateKey(ctx, n.ID, key("p")); err != nil {
			t.Fatal(err)
		}
		return n
	}
	return nw, mk("tun-a", "10.24.0.5", "A"), mk("tun-b", "10.24.0.6", "B")
}

// nftables mode: a network's tunnel mode decides which of its nodes use the
// hub as internet exit; a node override wins. Both go through the engine.
func TestNetworkTunnelModeWithEngine(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	nw, a, b := tunnelNetwork(t, s, "wg95", 51995)
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), nw.ID) })

	rec := call(t, s, "PUT", "/api/v1/networks/"+nw.ID+"/tunnel?confirm=false", `{"tunnel_mode":"full"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"affected_nodes":2`) {
		t.Fatalf("set full = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/networks/"+nw.ID+"/tunnel", rec)
	set := egressSet(r.last())
	if !strings.Contains(set, "10.24.0.5") || !strings.Contains(set, "10.24.0.6") {
		t.Fatalf("both nodes must be in the exit set: %q", set)
	}
	if got, _ := s.store.GetNetwork(context.Background(), nw.ID); got.TunnelMode != models.TunnelFull {
		t.Fatalf("stored mode = %q", got.TunnelMode)
	}
	if body := call(t, s, "GET", "/api/v1/nodes/"+a.ID+"/config", "").Body.String(); !strings.Contains(body, "AllowedIPs = 0.0.0.0/0\n") {
		t.Fatalf("a full network's node gets a full-tunnel config:\n%s", body)
	}

	rec = call(t, s, "PUT", "/api/v1/nodes/"+b.ID+"/tunnel?confirm=false", `{"tunnel_override":"split"}`)
	if rec.Code != 200 {
		t.Fatalf("override split = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/nodes/"+b.ID+"/tunnel", rec)
	if set := egressSet(r.last()); strings.Contains(set, "10.24.0.6") || !strings.Contains(set, "10.24.0.5") {
		t.Fatalf("a split override leaves the exit set: %q", set)
	}
	if got, _ := s.store.GetNode(context.Background(), b.ID); got.TunnelOverride != models.TunnelSplit {
		t.Fatalf("stored override = %q", got.TunnelOverride)
	}
	if rec := call(t, s, "PUT", "/api/v1/nodes/"+b.ID+"/tunnel?confirm=false", `{"tunnel_override":""}`); rec.Code != 200 {
		t.Fatalf("clear override = %d %s", rec.Code, rec.Body)
	}
	if set := egressSet(r.last()); !strings.Contains(set, "10.24.0.6") {
		t.Fatalf("without an override the node follows its full network: %q", set)
	}

	for path, body := range map[string]string{
		"/api/v1/networks/" + nw.ID + "/tunnel": `{"tunnel_mode":"tor"}`,
		"/api/v1/nodes/" + a.ID + "/tunnel":     `{"tunnel_override":"tor"}`,
	} {
		if rec := call(t, s, "PUT", path, body); rec.Code != 400 {
			t.Errorf("%s %s = %d, want 400", path, body, rec.Code)
		}
	}
	for _, path := range []string{"/api/v1/networks/00000000-0000-0000-0000-000000000000/tunnel", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/tunnel"} {
		if rec := call(t, s, "PUT", path, `{"tunnel_mode":"full","tunnel_override":"full"}`); rec.Code != 404 {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
}

// iptables mode (no engine): the hub's NAT comes from each network's
// wg-quick PostUp, so only configs change. The admin VPN (wg0, made by the
// installer without that PostUp) cannot go full without nftables.
func TestNetworkTunnelModeWithoutEngine(t *testing.T) {
	s, _, _ := newContractServer(t)
	nw, a, _ := tunnelNetwork(t, s, "wg96", 51996)
	rec := callAs(t, s, "PUT", "/api/v1/networks/"+nw.ID+"/tunnel", `{"tunnel_mode":"full"}`, true)
	if rec.Code != 200 {
		t.Fatalf("set full = %d %s", rec.Code, rec.Body)
	}
	if body := callAs(t, s, "GET", "/api/v1/nodes/"+a.ID+"/config", "", true).Body.String(); !strings.Contains(body, "AllowedIPs = 0.0.0.0/0\n") {
		t.Fatalf("full-tunnel config in iptables mode:\n%s", body)
	}
	admin, adminNode, _ := tunnelNetworkIface(t, s, "wg0", 51820, "10.25.0.0/24")
	rec = callAs(t, s, "PUT", "/api/v1/networks/"+admin.ID+"/tunnel", `{"tunnel_mode":"full"}`, true)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "full_tunnel_needs_nft") {
		t.Fatalf("admin VPN full in iptables mode = %d %s, want 409 full_tunnel_needs_nft", rec.Code, rec.Body)
	}
	rec = callAs(t, s, "PUT", "/api/v1/nodes/"+adminNode.ID+"/tunnel", `{"tunnel_override":"full"}`, true)
	if rec.Code != 409 {
		t.Fatalf("admin VPN node full in iptables mode = %d %s, want 409", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/nodes/"+adminNode.ID+"/tunnel", `{"tunnel_override":"split"}`, true); rec.Code != 200 {
		t.Fatalf("split is always allowed = %d %s", rec.Code, rec.Body)
	}
}

// A new network may be created full; that, like every tunnel change, gives
// nodes the hub as internet exit, so it needs an admin.
func TestTunnelModeNeedsAdmin(t *testing.T) {
	s, st, _ := newContractServer(t)
	nw, a, _ := tunnelNetwork(t, s, "wg97", 51997)
	op := roleSession(t, st, "contract-tunnel-op", "operator")
	if rec := callWith(t, s, op, "PUT", "/api/v1/networks/"+nw.ID+"/tunnel", `{"tunnel_mode":"full"}`); rec.Code != 403 {
		t.Errorf("operator network tunnel = %d, want 403", rec.Code)
	}
	if rec := callWith(t, s, op, "PUT", "/api/v1/nodes/"+a.ID+"/tunnel", `{"tunnel_override":"full"}`); rec.Code != 403 {
		t.Errorf("operator node tunnel = %d, want 403", rec.Code)
	}
	create := `{"name":"contract-tunnel-new","cidr":"10.26.0.0/24","tunnel_mode":"full"}`
	if rec := callWith(t, s, op, "POST", "/api/v1/networks", create); rec.Code != 403 {
		t.Errorf("operator creating a full network = %d %s, want 403", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"contract-tunnel-bad","cidr":"10.27.0.0/24","tunnel_mode":"tor"}`, true); rec.Code != 400 {
		t.Errorf("invalid tunnel mode = %d, want 400", rec.Code)
	}
	rec := callAs(t, s, "POST", "/api/v1/networks", create, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"tunnel_mode":"full"`) {
		t.Fatalf("admin creating a full network = %d %s", rec.Code, rec.Body)
	}
	if rec := callWith(t, s, op, "POST", "/api/v1/networks", `{"name":"contract-tunnel-split","cidr":"10.28.0.0/24"}`); rec.Code != 201 ||
		!strings.Contains(rec.Body.String(), `"tunnel_mode":"split"`) {
		t.Fatalf("operator creating a split network = %d %s", rec.Code, rec.Body)
	}
}

func tunnelNetworkIface(t *testing.T, s *Server, iface string, port int, cidr string) (*models.Network, *models.Node, *models.Node) {
	t.Helper()
	ctx := context.Background()
	key := func(c string) string { return strings.Repeat(c, 43) + "=" }
	nw := &models.Network{Name: "contract-tunnel-" + iface, CIDR: cidr, ServerPrivateKey: key("u"),
		ServerPublicKey: key("U"), ServerEndpoint: "203.0.113.1", InterfaceName: iface, ListenPort: port}
	if err := s.store.CreateNetwork(ctx, nw); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(cidr[:strings.LastIndex(cidr, ".")] + ".5")
	n := &models.Node{NetworkID: nw.ID, Name: "tun-admin", VirtualIP: ip, PublicKey: key("D"),
		Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := s.store.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	return nw, n, nil
}

// Shadow mode only checks rulesets (iptables enforces): a tunnel change is
// stored at once like in iptables mode, and the admin VPN cannot go full.
func TestNetworkTunnelModeInShadowMode(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeShadow)
	nw, _, _ := tunnelNetwork(t, s, "wg93", 51993)
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), nw.ID) })
	rec := call(t, s, "PUT", "/api/v1/networks/"+nw.ID+"/tunnel", `{"tunnel_mode":"full"}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"pending":{`) {
		t.Fatalf("shadow mode set full = %d %s, want 200 without a pending change", rec.Code, rec.Body)
	}
	if got, _ := s.store.GetNetwork(context.Background(), nw.ID); got.TunnelMode != models.TunnelFull {
		t.Fatalf("stored mode = %q", got.TunnelMode)
	}
}

// Asking for the mode a network or node already has changes nothing (no
// empty firewall change waiting for confirmation).
func TestTunnelModeUnchangedIsNoChange(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	nw, a, _ := tunnelNetwork(t, s, "wg92", 51992)
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), nw.ID) })
	applied := len(r.applied)
	for path, body := range map[string]string{
		"/api/v1/networks/" + nw.ID + "/tunnel": `{"tunnel_mode":"split"}`,
		"/api/v1/nodes/" + a.ID + "/tunnel":     `{"tunnel_override":""}`,
	} {
		rec := call(t, s, "PUT", path, body)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), `"pending":{`) || !strings.Contains(rec.Body.String(), `"affected_nodes":0`) {
			t.Errorf("%s unchanged = %d %s", path, rec.Code, rec.Body)
		}
	}
	if len(r.applied) != applied {
		t.Fatal("an unchanged mode must not touch the firewall")
	}
}

// Restoring a firewall snapshot taken before a network went full keeps the
// network full and its nodes in the internet exit set: tunnel modes are not
// part of what History restores.
func TestHistoryRestoreKeepsTunnelModes(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	db, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("DELETE FROM fw_history"); err != nil {
		t.Fatal(err)
	}
	s.firewall.History = s.store
	nw, _, _ := tunnelNetwork(t, s, "wg91", 51991)
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), nw.ID) })

	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services?confirm=false", `{"protocol":"tcp","port_from":9300}`); rec.Code != 200 {
		t.Fatalf("open 9300 = %d %s", rec.Code, rec.Body)
	}
	before := historyEntries(t, s)[0] // the state with 9300, network split
	if rec := call(t, s, "PUT", "/api/v1/networks/"+nw.ID+"/tunnel?confirm=false", `{"tunnel_mode":"full"}`); rec.Code != 200 {
		t.Fatalf("set full = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/history/"+before.ID+"/restore?confirm=false", ""); rec.Code != 200 {
		t.Fatalf("restore = %d %s", rec.Code, rec.Body)
	}
	if set := egressSet(r.last()); !strings.Contains(set, "10.24.0.5") || !strings.Contains(set, "10.24.0.6") {
		t.Fatalf("the full network's nodes must keep the exit after a restore: %q", set)
	}
	if got, _ := s.store.GetNetwork(context.Background(), nw.ID); got.TunnelMode != models.TunnelFull {
		t.Fatalf("network mode after restore = %q", got.TunnelMode)
	}
	nodes, _ := s.store.ListNodes(context.Background(), nw.ID)
	for _, n := range nodes {
		if n.TunnelOverride != "" {
			t.Fatalf("restore must not pin %s to %q", n.Name, n.TunnelOverride)
		}
	}
}
