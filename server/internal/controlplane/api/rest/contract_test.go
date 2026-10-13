package rest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
	"golang.org/x/crypto/bcrypt"
)

var updateContract = flag.Bool("update", false, "rewrite testdata/contract snapshots")

// wgCalls records what the stubbed WireGuard seams were asked to do.
var wgCalls []string

var (
	uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	timeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)
	keyRe  = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
)

// hostStub answers host commands from a table and records every call.
type hostStub struct {
	out   map[string]string
	calls []string
}

func (h *hostStub) run(name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	h.calls = append(h.calls, cmd)
	if o, ok := h.out[cmd]; ok {
		return o, nil
	}
	return "", fmt.Errorf("stub: %q is not available", cmd)
}

// newContractServer builds a Server on TEST_DATABASE_URL with empty
// networks and users and every host command stubbed.
func newContractServer(t *testing.T) (*Server, *store.Store, *hostStub) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run database tests (scripts/test-with-postgres.sh)")
	}
	st, err := store.New(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"DELETE FROM networks", "DELETE FROM users"} { // nodes and VPN rules cascade
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// Leave nothing behind: other packages share this database (networks.listen_port is unique).
	t.Cleanup(func() {
		db.Exec("DELETE FROM networks WHERE name LIKE 'contract-%'")
		db.Exec("DELETE FROM users WHERE username LIKE 'contract-%'")
		db.Close()
	})

	stub := &hostStub{out: map[string]string{}}
	origHost, origCmd, origKeys, origSSH, origLog := execHostCommand, execCommand, generateKeys, legacySSHPorts, openFail2BanLog
	execHostCommand, execCommand = stub.run, stub.run
	openFail2BanLog = func() (io.ReadCloser, error) { return nil, os.ErrNotExist }
	generateKeys = func() (string, string, error) {
		return strings.Repeat("k", 43) + "=", strings.Repeat("K", 43) + "=", nil
	}
	legacySSHPorts = func() []uint16 { return []uint16{22} }
	origInit, origTeardown, origUp := wgInit, wgTeardown, interfaceUp
	interfaceUp = func(string) bool { return true }
	wgCalls = nil
	wgInit = func(m *wireguard.Manager) error {
		wgCalls = append(wgCalls, "init "+m.InterfaceName)
		return fmt.Errorf("wireguard is disabled in tests")
	}
	wgTeardown = func(iface string) { wgCalls = append(wgCalls, "teardown "+iface) }
	t.Cleanup(func() { wgInit, wgTeardown, interfaceUp = origInit, origTeardown, origUp })
	t.Cleanup(func() {
		execHostCommand, execCommand, generateKeys, legacySSHPorts, openFail2BanLog = origHost, origCmd, origKeys, origSSH, origLog
	})

	s := &Server{store: st, router: mux.NewRouter(), managers: map[string]*wireguard.Manager{},
		peerActivity: map[string]*PeerActivity{}}
	s.setupRoutes()
	return s, st, stub
}

type contractSeed struct {
	network, empty *models.Network
	node           *models.Node
}

func seedContract(t *testing.T, st *store.Store) contractSeed {
	t.Helper()
	ctx := context.Background()
	key := func(c string) string { return strings.Repeat(c, 43) + "=" }
	n := &models.Network{Name: "contract-net", CIDR: "10.66.0.0/24", ServerPrivateKey: key("s"),
		ServerPublicKey: key("S"), ServerEndpoint: "203.0.113.1", ListenPort: 51866, InterfaceName: "wg66"}
	e := &models.Network{Name: "contract-zempty", CIDR: "10.68.0.0/24", ServerPrivateKey: key("e"),
		ServerPublicKey: key("E"), ListenPort: 51868, InterfaceName: "wg68"}
	for _, x := range []*models.Network{n, e} {
		if err := st.CreateNetwork(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	node := &models.Node{NetworkID: n.ID, Name: "contract-node", VirtualIP: net.ParseIP("10.66.0.3"),
		PublicKey: key("N"), Labels: map[string]string{"wireguard_private_key": key("P")}, Status: models.NodeStatusOnline}
	if err := st.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("contract-pw-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &models.User{Username: "contract-user", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	return contractSeed{network: n, empty: e, node: node}
}

func callAs(t *testing.T, s *Server, method, path, body string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.200:5555"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func normalizeBody(body string) string {
	body = strings.ReplaceAll(body, adminToken, "<token>")
	body = uuidRe.ReplaceAllString(body, "<uuid>")
	body = timeRe.ReplaceAllString(body, "<time>")
	return keyRe.ReplaceAllString(body, "<key>")
}

// assertContract compares status, content type and normalized body with
// testdata/contract/<name>.json (rewritten with -update).
func assertContract(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	body := normalizeBody(rec.Body.String())
	snap := map[string]interface{}{"status": rec.Code, "content_type": ct, "body": body}
	var parsed interface{}
	if strings.HasPrefix(ct, "application/json") && json.Unmarshal([]byte(body), &parsed) == nil {
		snap["body"] = parsed
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "contract", name+".json")
	if *updateContract {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run bash server/scripts/update-contracts.sh)", name, err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("%s: API contract changed\n--- want\n%s--- got\n%s", name, want, buf.Bytes())
	}
}

// fail2banIgnoreTree is real `fail2ban-client get sshd ignoreip` output.
const fail2banIgnoreTree = "These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n|- ::1\n`- 10.99.0.0/24\n"

// TestContract freezes the response shapes of every endpoint that can run
// without a host. Order matters: reads first, then writes.
func TestContract(t *testing.T) {
	s, st, stub := newContractServer(t)
	seed := seedContract(t, st)
	stub.out["fail2ban-client get sshd ignoreip"] = fail2banIgnoreTree
	openFail2BanLog = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(sampleF2BLog)), nil }
	n, e, node := seed.network.ID, seed.empty.ID, seed.node.ID
	missing := "00000000-0000-4000-8000-000000000000"

	cases := []struct {
		name, method, path, body string
		auth                     bool
	}{
		{"health", "GET", "/health", "", false},
		{"unauthorized", "GET", "/api/v1/networks", "", false},
		{"login_ok", "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"contract-pw-1"}`, false},
		{"login_bad", "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"wrong"}`, false},
		{"networks_list", "GET", "/api/v1/networks", "", true},
		{"network_get", "GET", "/api/v1/networks/" + n, "", true},
		{"network_get_missing", "GET", "/api/v1/networks/" + missing, "", true},
		{"nodes_list", "GET", "/api/v1/networks/" + n + "/nodes", "", true},
		{"nodes_list_empty", "GET", "/api/v1/networks/" + e + "/nodes", "", true},
		{"node_get", "GET", "/api/v1/nodes/" + node, "", true},
		{"node_config", "GET", "/api/v1/nodes/" + node + "/config", "", true},
		{"stats_overview", "GET", "/api/v1/stats/overview", "", true},
		{"users_list", "GET", "/api/v1/users", "", true},
		{"vpn_rules_list", "GET", "/api/v1/firewall/vpn/rules", "", true},
		{"fail2ban_whitelist", "GET", "/api/v1/system/fail2ban/whitelist", "", true},
		{"fail2ban_history", "GET", "/api/v1/system/fail2ban/ban-history", "", true},
		{"fail2ban_history_jail", "GET", "/api/v1/system/fail2ban/ban-history?jail=sshd&limit=2", "", true},
		{"network_create", "POST", "/api/v1/networks", `{"name":"contract-new","cidr":"10.67.0.0/24"}`, true},
		{"network_create_overlap", "POST", "/api/v1/networks", `{"name":"contract-overlap","cidr":"10.66.0.0/25"}`, true},
		{"network_create_bad_body", "POST", "/api/v1/networks", `{`, true},
		{"node_update", "PUT", "/api/v1/nodes/" + node, `{"name":"contract-node-renamed"}`, true},
		{"user_create", "POST", "/api/v1/users", `{"username":"contract-user-2","password":"contract-pw-2"}`, true},
		{"node_delete", "DELETE", "/api/v1/nodes/" + node, "", true},
	}
	for _, c := range cases {
		assertContract(t, c.name, callAs(t, s, c.method, c.path, c.body, c.auth))
	}
}

// B14: an empty collection is [] (VPNRuleModal maps over it), never null.
func TestEmptyCollectionsAreArrays(t *testing.T) {
	s, st, stub := newContractServer(t)
	stub.out["iptables -L INPUT -n --line-numbers"] = "Chain INPUT (policy DROP)\nnum  target     prot opt source               destination\n"
	for path, want := range map[string]string{
		"/api/v1/networks": "[]",
		"/api/v1/users":    "[]",
	} {
		if got := strings.TrimSpace(callAs(t, s, "GET", path, "", true).Body.String()); got != want {
			t.Errorf("GET %s = %s, want %s", path, got, want)
		}
	}
	e := &models.Network{Name: "contract-empty", CIDR: "10.69.0.0/24", ListenPort: 51869, InterfaceName: "wg69"}
	if err := st.CreateNetwork(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(callAs(t, s, "GET", "/api/v1/networks/"+e.ID+"/nodes", "", true).Body.String()); got != "[]" {
		t.Errorf("nodes of an empty network = %s, want []", got)
	}
	for path, key := range map[string]string{
		"/api/v1/system/fail2ban/ban-history":    `"history":[]`,
		"/api/v1/system/fail2ban/permanent-bans": `"permanent_bans":[]`,
	} {
		if got := callAs(t, s, "GET", path, "", true).Body.String(); !strings.Contains(got, key) {
			t.Errorf("GET %s = %s, want %s", path, got, key)
		}
	}
}

// Network create/delete must reach WireGuard only through the wgInit and
// wgTeardown seams, so tests never create an interface on the machine
// running them, even where wg is installed.
func TestNetworkHandlersUseWireGuardSeams(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st) // the first network would be wg0, the undeletable admin network
	rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"contract-seam","cidr":"10.75.0.0/24"}`, true)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var n models.Network
	if err := json.Unmarshal(rec.Body.Bytes(), &n); err != nil {
		t.Fatal(err)
	}
	if rec := callAs(t, s, "DELETE", "/api/v1/networks/"+n.ID, "", true); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	want := []string{"init " + n.InterfaceName, "teardown " + n.InterfaceName}
	if strings.Join(wgCalls, ",") != strings.Join(want, ",") {
		t.Fatalf("WireGuard calls = %v, want %v", wgCalls, want)
	}
}
