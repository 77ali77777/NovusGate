package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestEveryRouteIsDocumented fails when a route is registered without a
// docOps entry, or documented without being registered.
func TestEveryRouteIsDocumented(t *testing.T) {
	s, _, _ := newContractServer(t)
	registered := map[string]bool{}
	err := s.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil // catch-alls (api-fallback, spa) and the /api/v1 subrouter itself
		}
		for _, m := range methods {
			if m != "OPTIONS" {
				registered[m+" "+tpl] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, op := range docOps {
		documented[op.Method+" "+op.Path] = true
	}
	var missing, stale []string
	for k := range registered {
		if !documented[k] {
			missing = append(missing, k)
		}
	}
	for k := range documented {
		if !registered[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("undocumented routes:\n%s\ndocumented but not registered:\n%s", strings.Join(missing, "\n"), strings.Join(stale, "\n"))
	}
}

// TestContractOpenAPI keeps a golden copy of the document so every API
// change shows up in review (rewrite with -update, i.e. update-contracts.sh).
func TestContractOpenAPI(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(openAPIDocument()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "openapi.json")
	if *updateContract {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run bash server/scripts/update-contracts.sh)", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("OpenAPI document changed; review the diff and run update-contracts.sh")
	}
	doc := openAPIDocument()
	if doc["openapi"] != "3.0.3" {
		t.Fatalf("openapi = %v", doc["openapi"])
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"Error", "Network", "Node", "User", "VPNFirewallRule", "FirewallStatus", "OpenPortRequest"} {
		if schemas[name] == nil {
			t.Errorf("components.schemas.%s is missing", name)
		}
	}
	node := schemas["Node"].(map[string]any)["properties"].(map[string]any)
	if node["virtual_ip"].(map[string]any)["type"] != "string" || node["expires_at"].(map[string]any)["nullable"] != true {
		t.Errorf("Node schema: virtual_ip=%v expires_at=%v", node["virtual_ip"], node["expires_at"])
	}
}

func TestOpenAPIIsServedBehindAuth(t *testing.T) {
	s, _, _ := newContractServer(t)
	if rec := callAs(t, s, "GET", "/api/v1/openapi.json", "", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a token = %d, want 401", rec.Code)
	}
	rec := callAs(t, s, "GET", "/api/v1/openapi.json", "", true)
	var doc map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &doc) != nil || doc["paths"] == nil {
		t.Fatalf("with a token = %d %.200s", rec.Code, rec.Body)
	}
}
