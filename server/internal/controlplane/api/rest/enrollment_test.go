package rest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
)

var scriptTokenRe = regexp.MustCompile(`X-Enrollment-Token: ([0-9a-f]{64})`)

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
