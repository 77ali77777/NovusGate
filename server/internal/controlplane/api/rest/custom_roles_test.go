package rest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Custom roles (2026-10-20): every route an operator or viewer may use has a
// section, so a custom role decides it; a new route without one fails here.
func TestEverySharedRouteHasASection(t *testing.T) {
	for key := range viewerReads {
		if !personalRoutes[key] && !notForCustomRoles[key] && routeSections[key] == "" {
			t.Errorf("viewer read %s has no section", key)
		}
	}
	for key := range operatorRoutes {
		if routeSections[key] == "" {
			t.Errorf("operator route %s has no section", key)
		}
	}
	for key, role := range sensitiveReads {
		if role == "operator" && routeSections[key] == "" {
			t.Errorf("sensitive read %s has no section", key)
		}
	}
	for key := range routeSections {
		if requiredRole(strings.SplitN(key, " ", 2)[0], strings.SplitN(key, " ", 2)[1]) == "admin" {
			t.Errorf("%s is admin-only: a custom role may not get it", key)
		}
	}
}

// customUser makes a user with a new custom role and returns a session.
func customUser(t *testing.T, s *Server, username, body string) (string, string) {
	t.Helper()
	rec := callAs(t, s, "POST", "/api/v1/roles", body, true)
	if rec.Code != 201 {
		t.Fatalf("create role = %d %s", rec.Code, rec.Body)
	}
	var r models.Role
	json.Unmarshal(rec.Body.Bytes(), &r)
	token := roleSession(t, s.store, username, "viewer")
	u, _ := s.store.GetUserByUsername(context.Background(), username)
	if rec := callAs(t, s, "PUT", "/api/v1/users/"+u.ID+"/role", `{"role":"custom","role_id":"`+r.ID+`"}`, true); rec.Code != 200 {
		t.Fatalf("give role = %d %s", rec.Code, rec.Body)
	}
	t.Cleanup(func() {
		s.store.SetUserRole(context.Background(), u.ID, "viewer")
		s.store.DeleteRole(context.Background(), r.ID)
	})
	return token, r.ID
}

func TestCustomRoleDecidesWhatAUserCanDo(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	token, _ := customUser(t, s, "office-mgr", `{"name":"Office manager","permissions":{"networks":"view","devices":"edit"}}`)
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/api/v1/networks", "", 200},
		{"GET", "/api/v1/nodes/" + seed.node.ID, "", 200},
		{"PUT", "/api/v1/nodes/" + seed.node.ID, `{"name":"renamed"}`, 200},
		{"PUT", "/api/v1/networks/" + seed.network.ID + "/dns", `{"client_dns":""}`, 403}, // networks: view only
		{"GET", "/api/v1/firewall/vpn/rules", "", 403},                                    // no vpn_rules
		{"GET", "/api/v1/nodes/" + seed.node.ID + "/config", "", 403},                     // no configs
		{"GET", "/api/v1/users", "", 403},                                                 // admin only, always
		{"GET", "/api/v1/auth/me", "", 200},                                               // personal
	} {
		if rec := callWith(t, s, token, c.method, c.path, c.body); rec.Code != c.code {
			t.Errorf("%s %s = %d %s, want %d", c.method, c.path, rec.Code, rec.Body, c.code)
		}
	}
	var me struct {
		Role        string            `json:"role"`
		RoleName    string            `json:"role_name"`
		Permissions map[string]string `json:"permissions"`
	}
	json.Unmarshal(callWith(t, s, token, "GET", "/api/v1/auth/me", "").Body.Bytes(), &me)
	if me.Role != "custom" || me.RoleName != "Office manager" || me.Permissions["devices"] != "edit" || me.Permissions["vpn_rules"] != "none" {
		t.Fatalf("me = %+v", me)
	}
}

func TestBuiltInRolesReportTheirPermissions(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	for role, want := range map[string]map[string]string{
		"viewer":   {"devices": "view", "vpn_rules": "view", "configs": "none"},
		"operator": {"devices": "edit", "vpn_rules": "edit", "configs": "view", "host_firewall": "view"},
		"admin":    {"devices": "edit", "host_firewall": "edit", "configs": "view"},
	} {
		token := roleSession(t, st, "perm-"+role, role)
		var me struct {
			Permissions map[string]string `json:"permissions"`
		}
		json.Unmarshal(callWith(t, s, token, "GET", "/api/v1/auth/me", "").Body.Bytes(), &me)
		for k, v := range want {
			if me.Permissions[k] != v {
				t.Errorf("%s: %s = %q, want %q", role, k, me.Permissions[k], v)
			}
		}
	}
}

func TestRoleValidationAndDelete(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	for _, bad := range []string{
		`{"name":"","permissions":{}}`,
		`{"name":"x","permissions":{"unknown":"view"}}`,
		`{"name":"x","permissions":{"devices":"owner"}}`,
		`{"name":"x","permissions":{"host_firewall":"edit"}}`, // view only for custom roles
		`{"name":"x","permissions":{},"network_ids":["not-a-uuid"]}`,
		`{"name":"x","permissions":{},"network_ids":["00000000-0000-0000-0000-00000000dead"]}`,
	} {
		if rec := callAs(t, s, "POST", "/api/v1/roles", bad, true); rec.Code != 400 {
			t.Errorf("%s = %d %s", bad, rec.Code, rec.Body)
		}
	}
	token, id := customUser(t, s, "role-holder", `{"name":"Holder","permissions":{"dashboard":"view"}}`)
	if rec := callAs(t, s, "DELETE", "/api/v1/roles/"+id, "", true); rec.Code != 409 {
		t.Fatalf("delete in use = %d %s", rec.Code, rec.Body)
	}
	if rec := callWith(t, s, token, "GET", "/api/v1/roles", ""); rec.Code != 403 {
		t.Fatalf("roles are admin only: %d", rec.Code)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/roles/"+id, `{"name":"Holder","permissions":{"dashboard":"view","audit":"view"}}`, true); rec.Code != 200 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if rec := callWith(t, s, token, "GET", "/api/v1/audit", ""); rec.Code != 200 {
		t.Fatalf("a changed role applies at once: %d", rec.Code)
	}
}

// R2: a role limited to networks sees and changes only those, and only the
// sections that stay inside one network.
func TestRoleLimitedToNetworks(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	token, _ := customUser(t, s, "scoped-mgr", `{"name":"Scoped","permissions":{"networks":"edit","devices":"edit","configs":"view","vpn_rules":"edit"},"network_ids":["`+seed.network.ID+`"]}`)
	var nets []models.Network
	json.Unmarshal(callWith(t, s, token, "GET", "/api/v1/networks", "").Body.Bytes(), &nets)
	if len(nets) != 1 || nets[0].ID != seed.network.ID {
		t.Fatalf("only its network: %+v", nets)
	}
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/api/v1/networks/" + seed.network.ID, "", 200},
		{"GET", "/api/v1/networks/" + seed.empty.ID, "", 403},
		{"GET", "/api/v1/networks/" + seed.empty.ID + "/nodes", "", 403},
		{"GET", "/api/v1/nodes/" + seed.node.ID + "/config", "", 200},
		{"POST", "/api/v1/networks", `{"name":"mine"}`, 403}, // a new network is outside its scope
		{"GET", "/api/v1/firewall/vpn/rules", "", 403},       // rules span networks
		{"POST", "/api/v1/networks/" + seed.empty.ID + "/servers", `{"name":"x"}`, 403},
	} {
		if rec := callWith(t, s, token, c.method, c.path, c.body); rec.Code != c.code {
			t.Errorf("%s %s = %d %s, want %d", c.method, c.path, rec.Code, rec.Body, c.code)
		}
	}
	_ = mux.Vars
}

// Review: "devices: edit" without "configs" creates devices, but the new
// device's config (its private key) is not handed out.
func TestDeviceEditWithoutConfigsGetsNoKey(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	token, _ := customUser(t, s, "no-configs", `{"name":"Devices only","permissions":{"networks":"view","devices":"edit"}}`)
	rec := callWith(t, s, token, "POST", "/api/v1/networks/"+seed.network.ID+"/servers", `{"name":"made-by-role"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PrivateKey") {
		t.Fatalf("no configs permission, no private key: %s", rec.Body)
	}
}

// Review: a deleted network stays in a role limited to networks (fail
// closed: the role does not turn into "every network"), and the role can
// still be saved.
func TestRoleKeepsADeletedNetwork(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	_, id := customUser(t, s, "scope-gone", `{"name":"Gone","permissions":{"devices":"view"},"network_ids":["`+seed.empty.ID+`"]}`)
	if err := st.DeleteNetwork(context.Background(), seed.empty.ID); err != nil {
		t.Fatal(err)
	}
	rec := callAs(t, s, "PUT", "/api/v1/roles/"+id, `{"name":"Gone","permissions":{"devices":"view"},"network_ids":["`+seed.empty.ID+`"]}`, true)
	if rec.Code != 200 {
		t.Fatalf("save with the deleted network = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/roles/"+id, `{"name":"Gone","permissions":{},"network_ids":["00000000-0000-0000-0000-00000000beef"]}`, true); rec.Code != 400 {
		t.Fatalf("a network it never had is still refused: %d", rec.Code)
	}
}

// Review: the scope check fails closed on a device id it cannot look up.
func TestScopedRoleRefusesAnUnreadableDeviceID(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	token, _ := customUser(t, s, "scoped-bad-id", `{"name":"Scoped bad id","permissions":{"devices":"view"},"network_ids":["`+seed.network.ID+`"]}`)
	if rec := callWith(t, s, token, "GET", "/api/v1/nodes/not-a-uuid", ""); rec.Code != 403 {
		t.Fatalf("unreadable id = %d %s", rec.Code, rec.Body)
	}
}
