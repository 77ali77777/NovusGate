package rest

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
)

var scriptTokenRe = regexp.MustCompile(`X-Enrollment-Token: %s\\n' '([0-9a-f]{64})'`)

// installToken fetches a node's install script with the panel session and
// returns the script and the enrollment token in it.
func installToken(t *testing.T, s *Server, nodeID string) (string, string) {
	t.Helper()
	rec := callAs(t, s, "GET", "/api/v1/nodes/"+nodeID+"/install.sh", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("install.sh = %d %s", rec.Code, rec.Body)
	}
	m := scriptTokenRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no enrollment token in the script:\n%s", rec.Body)
	}
	return rec.Body.String(), m[1]
}

// enrollCheckin posts a checkin with only an enrollment token.
func enrollCheckin(s *Server, nodeID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/v1/nodes/"+nodeID+"/checkin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enrollment-Token", token)
	req.RemoteAddr = "10.66.0.3:40000"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func TestInstallScript(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	script, _ := installToken(t, s, seed.node.ID)
	if ct := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID+"/install.sh", "", true).Header().Get("Content-Type"); ct != "text/x-shellscript" {
		t.Errorf("content type = %q", ct)
	}
	for _, want := range []string{
		"<<'WGCONF'",
		"http://10.66.0.1:8080/api/v1/nodes/" + seed.node.ID + "/checkin",
		`"arch":"%s"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	umask, write := strings.Index(script, "umask 077"), strings.Index(script, "cat > /etc/wireguard/wg0.conf")
	if umask < 0 || umask > write {
		t.Errorf("umask 077 must come before the config is written (umask at %d, write at %d)", umask, write)
	}
	// wg-quick applies a DNS line through resolvconf, which Ubuntu does not
	// ship; resolvectl speaks it when called by that name.
	dns := strings.Index(script, "ln -sf \"$(command -v resolvectl)\" /usr/local/sbin/resolvconf")
	if dns < 0 || dns > strings.Index(script, "systemctl restart wg-quick@wg0") || !strings.Contains(script, "apt-get install -y openresolv") {
		t.Errorf("no resolvconf before the tunnel starts (at %d)", dns)
	}
	up, checkin := strings.Index(script, "systemctl restart wg-quick@wg0"), strings.Index(script, "X-Enrollment-Token")
	if up < 0 || checkin < 0 || up > checkin {
		t.Errorf("WireGuard must be up before the checkin (up at %d, checkin at %d)", up, checkin)
	}
}

func TestEnrollmentCheckin(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	node := seed.node.ID
	body := `{"node_info":{"os":"Linux","arch":"x86_64","hostname":"edge-9"}}`

	_, token := installToken(t, s, node)
	if rec := enrollCheckin(s, node, token, body); rec.Code != http.StatusOK {
		t.Fatalf("first use = %d %s", rec.Code, rec.Body)
	}
	if rec := enrollCheckin(s, node, token, body); rec.Code != http.StatusUnauthorized || errorCode(t, rec.Body.Bytes()) != "invalid_enrollment_token" {
		t.Fatalf("second use = %d %s, want 401 invalid_enrollment_token", rec.Code, rec.Body)
	}

	other := createTestNode(t, st, seed.network.ID, "contract-other-node", "10.66.0.9")
	_, token = installToken(t, s, node)
	if rec := enrollCheckin(s, other, token, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another node's token = %d, want 401", rec.Code)
	}

	orig := authNow
	t.Cleanup(func() { authNow = orig })
	authNow = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if rec := enrollCheckin(s, node, token, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d, want 401", rec.Code)
	}
}

func TestEnrollmentHeaderOnlyOpensCheckin(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	_, token := installToken(t, s, seed.node.ID)
	for _, p := range []string{"/api/v1/networks", "/api/v1/nodes/" + seed.node.ID} {
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("X-Enrollment-Token", token)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with only an enrollment token = %d, want 401", p, rec.Code)
		}
	}
}

func TestCheckinIgnoresWireguardLabels(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	body := `{"labels":{"wireguard_private_key":"stolen","mac_address":"aa:bb"}}`
	if rec := callAs(t, s, "POST", "/api/v1/nodes/"+seed.node.ID+"/checkin", body, true); rec.Code != http.StatusOK {
		t.Fatalf("checkin = %d %s", rec.Code, rec.Body)
	}
	got, err := st.GetNode(context.Background(), seed.node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels["wireguard_private_key"] == "stolen" || got.Labels["mac_address"] != "aa:bb" {
		t.Fatalf("labels = %v", got.Labels)
	}
}

func createTestNode(t *testing.T, st *store.Store, networkID, name, ip string) string {
	t.Helper()
	n := &models.Node{NetworkID: networkID, Name: name, VirtualIP: net.ParseIP(ip),
		PublicKey: strings.Repeat("Q", 43) + "=", Labels: map[string]string{}, Status: models.NodeStatusPending}
	if err := st.CreateNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n.ID
}

// The generated script must at least be valid bash.
func TestInstallScriptIsValidBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	script := installScript("[Interface]\nPrivateKey = k$x`y`\nAddress = 10.66.0.3", "http://10.66.0.1:8080/api/v1/nodes/n/checkin", strings.Repeat("a", 64))
	cmd := exec.Command(bash, "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

// Deployments always set the API key; the enrollment checkin must pass it
// and nothing else may.
func TestEnrollmentWithAPIKey(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	orig := apiKey
	t.Cleanup(func() { apiKey = orig })
	apiKey = "contract-api-key"

	req := httptest.NewRequest("GET", "/api/v1/nodes/"+seed.node.ID+"/install.sh", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	m := scriptTokenRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		t.Fatalf("install.sh = %d %s", rec.Code, rec.Body)
	}
	token := m[1]

	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/networks"},
		{"GET", "/api/v1/nodes/" + seed.node.ID + "/checkin"},
		{"PUT", "/api/v1/nodes/" + seed.node.ID},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(`{}`))
		req.Header.Set(enrollmentHeader, token)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with only an enrollment token = %d, want 401", c.method, c.path, rec.Code)
		}
	}
	if rec := enrollCheckin(s, seed.node.ID, token, `{"node_info":{"os":"Linux"}}`); rec.Code != http.StatusOK {
		t.Fatalf("enrollment checkin with the API key enabled = %d %s", rec.Code, rec.Body)
	}
}

// A checkin whose body is rejected must
// not burn the token.
func TestEnrollmentTokenSurvivesRejectedCheckin(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	_, token := installToken(t, s, seed.node.ID)
	if rec := enrollCheckin(s, seed.node.ID, token, `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d, want 400", rec.Code)
	}
	if rec := enrollCheckin(s, seed.node.ID, token, `{"node_info":{"os":"Linux"}}`); rec.Code != http.StatusOK {
		t.Fatalf("the token must still work after a rejected body: %d %s", rec.Code, rec.Body)
	}
}

func TestInstallScriptHardening(t *testing.T) {
	script := installScript("[Interface]", "http://10.66.0.1:8080/api/v1/nodes/n/checkin", strings.Repeat("b", 64))
	for _, want := range []string{
		"command -v curl",       // curl even when wg is already installed
		"tr -cd 'A-Za-z0-9._-'", // hostname and arch cannot break the JSON
		`-H @"$HDR"`,            // the token is not in curl's argv
		"401)",                  // a used or expired token stops at once
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "curl ") && strings.Contains(line, strings.Repeat("b", 64)) {
			t.Errorf("the token is on a curl command line: %s", line)
		}
	}
}

// An unauthenticated checkin body is capped before it is decoded.
func TestEnrollmentCheckinBodyIsCapped(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	big := `{"labels":{"x":"` + strings.Repeat("a", 2<<20) + `"}}`
	if rec := enrollCheckin(s, seed.node.ID, strings.Repeat("0", 64), big); rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
		t.Fatalf("a 2 MiB body = %d, want it refused", rec.Code)
	}
	_, token := installToken(t, s, seed.node.ID)
	if rec := enrollCheckin(s, seed.node.ID, token, big); rec.Code == http.StatusOK {
		t.Fatal("even with a valid token a 2 MiB body must be refused")
	}
}

// HEAD on install.sh must not mint an enrollment token.
func TestHeadInstallScriptMintsNoToken(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	db, _ := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	defer db.Close()
	count := func() (n int) {
		db.QueryRow("SELECT count(*) FROM enrollment_tokens WHERE node_id = $1", seed.node.ID).Scan(&n)
		return n
	}
	before := count()
	if rec := serveFull(s, "HEAD", "/api/v1/nodes/"+seed.node.ID+"/install.sh", true); rec.Code != http.StatusOK {
		t.Fatalf("HEAD = %d", rec.Code)
	}
	if count() != before {
		t.Fatal("HEAD must not create an enrollment token")
	}
}

// A checkin whose token was valid when the update ran, but whose response
// was lost, is not counted as used before the node is stored.
func TestEnrollmentTokenIsUsedOnlyAfterTheUpdate(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	_, token := installToken(t, s, seed.node.ID)
	db, _ := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	defer db.Close()
	// Make UpdateNode fail for this request only.
	defer db.Exec("DROP TRIGGER IF EXISTS contract_fail_update ON nodes")
	db.Exec(`CREATE OR REPLACE FUNCTION contract_fail_update() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'update blocked by test'; END $$ LANGUAGE plpgsql`)
	db.Exec(`CREATE TRIGGER contract_fail_update BEFORE UPDATE ON nodes FOR EACH ROW EXECUTE FUNCTION contract_fail_update()`)
	rec := enrollCheckin(s, seed.node.ID, token, `{"node_info":{"os":"Linux"}}`)
	db.Exec("DROP TRIGGER contract_fail_update ON nodes")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("blocked update = %d, want 500", rec.Code)
	}
	if rec := enrollCheckin(s, seed.node.ID, token, `{"node_info":{"os":"Linux"}}`); rec.Code != http.StatusOK {
		t.Fatalf("the retry after a failed update = %d %s, want 200 (token not used yet)", rec.Code, rec.Body)
	}
}
