package rest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func clearLimits(t *testing.T) {
	t.Helper()
	clearRows(t, "UPDATE nodes SET limit_profile_id = NULL")
	clearRows(t, "UPDATE node_groups SET limit_profile_id = NULL")
	clearTable(t, "limit_profiles")
}

func TestLimitProfilesCRUD(t *testing.T) {
	s, _, _ := newContractServer(t)
	_, a, b := groupNodes(t, s)
	clearLimits(t)

	body := `{"name":"office","down_kbps":2000,"up_kbps":null,"max_connections":50,"timezone":"Asia/Baku",
		"schedule":[{"days":[1,2,3,4,5],"from":"08:00","to":"18:00"}]}`
	rec := callAs(t, s, "POST", "/api/v1/limits", body, true)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "POST", "/api/v1/limits", rec)
	var p models.LimitProfile
	json.Unmarshal(rec.Body.Bytes(), &p)
	if p.ID == "" || p.DownKbps == nil || *p.DownKbps != 2000 || p.UpKbps != nil || len(p.NodeIDs) != 0 {
		t.Fatalf("created = %+v", p)
	}
	for name, bad := range map[string]string{
		"duplicate": `{"name":"office","down_kbps":1,"timezone":"UTC"}`,
		"bad zone":  `{"name":"x","down_kbps":1,"timezone":"Mars/Olympus"}`,
		"no limit":  `{"name":"x","timezone":"UTC"}`,
		"bad time":  `{"name":"x","timezone":"UTC","schedule":[{"days":[1],"from":"25:00","to":"26:00"}]}`,
		"not json":  `{`,
	} {
		want := 400
		if name == "duplicate" {
			want = 409
		}
		if rec := callAs(t, s, "POST", "/api/v1/limits", bad, true); rec.Code != want {
			t.Errorf("%s = %d %s, want %d", name, rec.Code, rec.Body, want)
		}
	}

	// Bind a directly and b through a group.
	g := &models.NodeGroup{Name: "limited"}
	if err := s.store.CreateNodeGroup(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	s.store.SetNodeGroupMembers(context.Background(), g.ID, []string{b.ID})
	rec = callAs(t, s, "PUT", "/api/v1/limits/"+p.ID+"/bindings",
		`{"node_ids":["`+a.ID+`"],"group_ids":["`+g.ID+`"]}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), a.ID) {
		t.Fatalf("bindings = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/limits/{id}/bindings", rec)
	if rec := callAs(t, s, "PUT", "/api/v1/limits/"+p.ID+"/bindings",
		`{"node_ids":["00000000-0000-0000-0000-000000000000"],"group_ids":[]}`, true); rec.Code != 400 {
		t.Fatalf("unknown node = %d %s", rec.Code, rec.Body)
	}

	list := callAs(t, s, "GET", "/api/v1/limits", "", true)
	if list.Code != 200 {
		t.Fatalf("list = %d %s", list.Code, list.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/limits", list)
	var resp LimitProfilesResponse
	json.Unmarshal(list.Body.Bytes(), &resp)
	if len(resp.Profiles) != 1 || len(resp.NodeLimits) != 2 {
		t.Fatalf("list = %s", list.Body)
	}
	for _, l := range resp.NodeLimits {
		if l.NodeID == b.ID && l.GroupID != g.ID {
			t.Errorf("b must inherit through the group: %+v", l)
		}
	}

	rec = callAs(t, s, "PUT", "/api/v1/limits/"+p.ID, `{"name":"office-2","up_kbps":512,"timezone":"UTC"}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"up_kbps":512`) || !strings.Contains(rec.Body.String(), a.ID) {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "PUT", "/api/v1/limits/{id}", rec)

	if rec := callAs(t, s, "DELETE", "/api/v1/limits/"+p.ID, "", true); rec.Code != 409 {
		t.Fatalf("delete while bound = %d %s", rec.Code, rec.Body)
	}
	callAs(t, s, "PUT", "/api/v1/limits/"+p.ID+"/bindings", `{"node_ids":[],"group_ids":[]}`, true)
	if rec := callAs(t, s, "DELETE", "/api/v1/limits/"+p.ID, "", true); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/api/v1/limits/" + p.ID, "/api/v1/limits/not-a-uuid"} {
		if rec := callAs(t, s, "DELETE", path, "", true); rec.Code != 404 {
			t.Errorf("delete %s = %d", path, rec.Code)
		}
	}
	if rec := callAs(t, s, "PUT", "/api/v1/limits/not-a-uuid/bindings", `{"node_ids":[]}`, true); rec.Code != 404 {
		t.Errorf("bindings on bad id = %d", rec.Code)
	}
}

// Viewers may read the limits; operators may change them.
func TestLimitRoles(t *testing.T) {
	s, st, _ := newContractServer(t)
	clearLimits(t)
	viewer := roleSession(t, st, "limit-viewer", "viewer")
	operator := roleSession(t, st, "limit-operator", "operator")
	if rec := callWith(t, s, viewer, "GET", "/api/v1/limits", ""); rec.Code != 200 {
		t.Errorf("viewer read = %d", rec.Code)
	}
	if rec := callWith(t, s, viewer, "POST", "/api/v1/limits", `{"name":"v","up_kbps":1,"timezone":"UTC"}`); rec.Code != 403 {
		t.Errorf("viewer create = %d", rec.Code)
	}
	if rec := callWith(t, s, operator, "POST", "/api/v1/limits", `{"name":"o","up_kbps":1,"timezone":"UTC"}`); rec.Code != 201 {
		t.Errorf("operator create = %d %s", rec.Code, rec.Body)
	}
}
