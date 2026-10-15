package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
	"golang.org/x/crypto/bcrypt"
)

// roleSession creates (or reuses) a user with role and returns a session token.
func roleSession(t *testing.T, st *store.Store, username, role string) string {
	t.Helper()
	ctx := context.Background()
	u, err := st.GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		hash, _ := bcrypt.GenerateFromPassword([]byte("role-pw-1"), bcrypt.MinCost)
		u = &models.User{Username: username, PasswordHash: string(hash), Role: role}
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.DeleteUser(context.Background(), u.ID) })
	}
	token, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, u.ID, hashToken(token), time.Now(), sessionTTL); err != nil {
		t.Fatal(err)
	}
	return token
}

func callWith(t *testing.T, s *Server, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	saved := adminToken
	adminToken = token
	defer func() { adminToken = saved }()
	return callAs(t, s, method, path, body, true)
}

func TestRolesLimitWhatUsersCanDo(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	viewer := roleSession(t, st, "role-viewer", "viewer")
	operator := roleSession(t, st, "role-operator", "operator")

	for _, c := range []struct {
		token, method, path, body string
		want                      int
	}{
		{viewer, "GET", "/api/v1/networks", "", 200},
		{viewer, "POST", "/api/v1/networks", `{"name":"v-net","cidr":"10.95.0.0/24"}`, 403},
		{viewer, "GET", "/api/v1/nodes/" + seed.node.ID + "/config", "", 403},     // private key
		{viewer, "GET", "/api/v1/nodes/" + seed.node.ID + "/install.sh", "", 403}, // creates an enrollment token
		{viewer, "GET", "/api/v1/firewall/vpn/rules", "", 200},
		{viewer, "POST", "/api/v1/auth/logout", "", 204}, // own session
		{operator, "POST", "/api/v1/networks", `{"name":"o-net","cidr":"10.96.0.0/24"}`, 201},
		{operator, "GET", "/api/v1/nodes/" + seed.node.ID + "/config", "", 200},
		{operator, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9}`, 403},
		{operator, "POST", "/api/v1/users", `{"username":"x","password":"y1y2y3"}`, 403},
		{operator, "GET", "/api/v1/backups/novusgate-backup-20261015-000000.tar.gz", "", 403},
		{operator, "GET", "/api/v1/audit", "", 200},
		{operator, "GET", "/api/v1/firewall/host/export", "", 403},                 // whole host ruleset
		{operator, "POST", "/api/v1/nodes/" + seed.node.ID + "/checkin", `{`, 400}, // operators manage nodes
	} {
		rec := callWith(t, s, c.token, c.method, c.path, c.body)
		if rec.Code != c.want {
			t.Errorf("%s %s as %s… = %d, want %d: %s", c.method, c.path, c.token[:6], rec.Code, c.want, rec.Body)
		}
		if c.want == 403 && errorCode(t, rec.Body.Bytes()) != "forbidden" {
			t.Errorf("%s %s: code %s", c.method, c.path, rec.Body)
		}
	}
	// A viewer may still change their own password.
	// (a new session: the logout above ended the first one)
	viewer = roleSession(t, st, "role-viewer", "viewer")
	rec := callWith(t, s, viewer, "PUT", "/api/v1/auth/password", `{"username":"role-viewer","oldPassword":"role-pw-1","newPassword":"role-pw-2"}`)
	if rec.Code != 200 {
		t.Errorf("viewer password = %d %s", rec.Code, rec.Body)
	}
}

func TestUserRolesAndLastAdmin(t *testing.T) {
	s, st, _ := newContractServer(t)
	ctx := context.Background()
	// Only the contract admin is an admin.
	users, _ := st.ListUsers(ctx)
	for _, u := range users {
		if u.Username != "contract-user" {
			st.DeleteUser(ctx, u.ID)
		}
	}

	rec := callAs(t, s, "POST", "/api/v1/users", `{"username":"new-viewer","password":"pw-123456","role":"viewer"}`, true)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"role":"viewer"`) {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var created models.User
	json.Unmarshal(rec.Body.Bytes(), &created)
	if rec := callAs(t, s, "POST", "/api/v1/users", `{"username":"bad-role","password":"pw-123456","role":"root"}`, true); rec.Code != 400 {
		t.Fatalf("bad role = %d", rec.Code)
	}

	rec = callAs(t, s, "PUT", "/api/v1/users/"+created.ID+"/role", `{"role":"operator"}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"operator"`) {
		t.Fatalf("set role = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/users/{id}/role", rec)
	// Any UUID spelling names the same user; a non-UUID is an unknown one.
	rec = callAs(t, s, "PUT", "/api/v1/users/"+strings.ToUpper(created.ID)+"/role", `{"role":"viewer"}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"viewer"`) {
		t.Fatalf("set role, upper-case id = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/users/not-a-uuid/role", `{"role":"viewer"}`, true); rec.Code != 404 {
		t.Fatalf("set role, bad id = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "DELETE", "/api/v1/users/not-a-uuid", "", true); rec.Code != 404 {
		t.Fatalf("delete, bad id = %d %s", rec.Code, rec.Body)
	}

	admin, _ := st.GetUserByUsername(ctx, "contract-user")
	if rec := callAs(t, s, "PUT", "/api/v1/users/"+admin.ID+"/role", `{"role":"viewer"}`, true); rec.Code != 409 {
		t.Fatalf("demote last admin = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "DELETE", "/api/v1/users/"+admin.ID, "", true); rec.Code != 409 && rec.Code != 400 {
		t.Fatalf("delete last admin = %d %s", rec.Code, rec.Body)
	}

	me := callAs(t, s, "GET", "/api/v1/auth/me", "", true)
	if me.Code != 200 || !strings.Contains(me.Body.String(), `"role":"admin"`) || !strings.Contains(me.Body.String(), "contract-user") {
		t.Fatalf("me = %d %s", me.Code, me.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/auth/me", me)
	list := callAs(t, s, "GET", "/api/v1/users", "", true)
	if !strings.Contains(list.Body.String(), `"username":"new-viewer","role":"viewer"`) {
		t.Fatalf("list = %s", list.Body)
	}
}

// Every route the operator allow-list names exists, so the list cannot go
// stale; everything not listed needs an admin.
func TestOperatorRoutesExist(t *testing.T) {
	s, _, _ := newContractServer(t)
	routes := map[string]bool{}
	s.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, _ := route.GetMethods()
		for _, m := range methods {
			routes[m+" "+tpl] = true
		}
		return nil
	})
	for key := range operatorRoutes {
		if !routes[key] {
			t.Errorf("operatorRoutes names %q, which is not a route", key)
		}
	}
	for key := range sensitiveReads {
		if !routes[key] {
			t.Errorf("sensitiveReads names %q, which is not a route", key)
		}
	}
	for key := range viewerReads {
		if !routes[key] {
			t.Errorf("viewerReads names %q, which is not a route", key)
		}
	}
	// Every read is classified, so a new GET cannot reach viewers by default.
	for key := range routes {
		if strings.HasPrefix(key, "GET /api/v1/") && !viewerReads[key] && sensitiveReads[key] == "" {
			t.Errorf("%s is in neither viewerReads nor sensitiveReads", key)
		}
	}
	_ = http.MethodGet
}
