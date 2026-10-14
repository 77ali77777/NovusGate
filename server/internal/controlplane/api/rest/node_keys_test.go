package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
)

// Node responses never carry the private key; has_config says whether the
// server can still produce the node's config.
func TestNodeJSONHasNoPrivateKey(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	rec := callAs(t, s, "POST", "/api/v1/networks/"+seed.network.ID+"/servers", `{"name":"contract-keyed"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created CreateServerResponse
	decodeJSON(t, rec, &created)
	for _, path := range []string{"/api/v1/nodes/" + created.Node.ID, "/api/v1/networks/" + seed.network.ID + "/nodes"} {
		body := callAs(t, s, "GET", path, "", true).Body.String()
		if strings.Contains(body, "wireguard_private_key") {
			t.Errorf("GET %s leaks the private key label: %s", path, body)
		}
	}
	if strings.Contains(rec.Body.String(), "wireguard_private_key") {
		t.Errorf("create response leaks the private key label")
	}
	var node struct {
		HasConfig bool `json:"has_config"`
	}
	json.Unmarshal(callAs(t, s, "GET", "/api/v1/nodes/"+created.Node.ID, "", true).Body.Bytes(), &node)
	if !node.HasConfig {
		t.Error("a node created with a config must report has_config")
	}
	cfg := callAs(t, s, "GET", "/api/v1/nodes/"+created.Node.ID+"/config", "", true)
	if cfg.Code != http.StatusOK || !strings.Contains(cfg.Body.String(), "PrivateKey = ") {
		t.Fatalf("config = %d %s", cfg.Code, cfg.Body)
	}
}

// A firewall audit entry records the panel user who made the change.
func TestFirewallAuditRecordsUser(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeNft)
	if rec := call(t, s, "POST", "/api/v1/firewall/vpn/apply", ""); rec.Code != http.StatusOK {
		t.Fatalf("apply = %d %s", rec.Code, rec.Body)
	}
	db, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var username sql.NullString
	err = db.QueryRowContext(context.Background(), `
		SELECT u.username FROM firewall_audit_log a LEFT JOIN users u ON u.id = a.user_id
		WHERE a.action = 'vpn_rules_applied' ORDER BY a.created_at DESC LIMIT 1`).Scan(&username)
	if err != nil {
		t.Fatal(err)
	}
	if username.String != "engine-admin" {
		t.Fatalf("audit user = %q, want engine-admin", username.String)
	}
}

// The create-server body cannot plant a key label either.
func TestCreateServerIgnoresWireguardLabels(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	rec := callAs(t, s, "POST", "/api/v1/networks/"+seed.network.ID+"/servers",
		`{"name":"contract-planted","labels":{"wireguard_private_key":"junk","role":"db"}}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created CreateServerResponse
	decodeJSON(t, rec, &created)
	got, err := st.GetNode(context.Background(), created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Labels["wireguard_private_key"]; ok || got.Labels["role"] != "db" {
		t.Fatalf("labels = %v", got.Labels)
	}
	if key, _ := st.NodePrivateKey(context.Background(), created.Node.ID); key == "junk" || key == "" {
		t.Fatalf("stored key = %q, want the generated one", key)
	}
}
