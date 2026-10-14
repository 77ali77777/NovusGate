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

// undocumentedRoutes compares the router with docOps. A route without
// methods counts as "ANY <path>" unless it is a named catch-all
// (api-fallback, spa) or a subrouter prefix.
func undocumentedRoutes(r *mux.Router, ops []docOp) (missing, stale []string) {
	registered := map[string]bool{}
	_ = r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			if name := route.GetName(); name == "api-fallback" || name == "spa" || route.GetHandler() == nil {
				return nil // catch-alls and subrouter prefixes
			}
			registered["ANY "+tpl] = true
			return nil
		}
		for _, m := range methods {
			if m != "OPTIONS" {
				registered[m+" "+tpl] = true
			}
		}
		return nil
	})
	documented := map[string]bool{}
	for _, op := range ops {
		documented[op.Method+" "+op.Path] = true
	}
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
	return missing, stale
}

// TestEveryRouteIsDocumented fails when a route is registered without a
// docOps entry, or documented without being registered.
func TestEveryRouteIsDocumented(t *testing.T) {
	s, _, _ := newContractServer(t)
	missing, stale := undocumentedRoutes(s.router, docOps)
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

// Requests are decoded with every field optional (Go fills zero values and
// handlers apply defaults); only responses follow omitempty.
func TestRequestSchemasHaveNoRequiredFields(t *testing.T) {
	schemas := openAPIDocument()["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"OpenPortRequest", "ClosePortRequest", "BlockIPRequest", "v2ServiceRequest", "v2IPRuleRequest", "VPNFirewallRuleRequest"} {
		if req := schemas[name].(map[string]any)["required"]; req != nil {
			t.Errorf("%s.required = %v; request fields are optional on decode", name, req)
		}
	}
	if schemas["Node"].(map[string]any)["required"] == nil {
		t.Error("response schemas keep their required fields")
	}
}

// A route registered without .Methods(...) must be reported too, unless it
// is one of the two named catch-alls or a subrouter prefix.
func TestUndocumentedRoutesCatchesMethodlessRoutes(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/ws", func(http.ResponseWriter, *http.Request) {})
	r.HandleFunc("/api/v1/networks", func(http.ResponseWriter, *http.Request) {}).Methods("GET")
	r.PathPrefix("/api/").HandlerFunc(func(http.ResponseWriter, *http.Request) {}).Name("api-fallback")
	r.PathPrefix("/api/v2").Subrouter()
	missing, stale := undocumentedRoutes(r, []docOp{{Method: "GET", Path: "/api/v1/networks"}, {Method: "GET", Path: "/gone"}})
	if strings.Join(missing, ",") != "ANY /api/v1/ws" || strings.Join(stale, ",") != "GET /gone" {
		t.Fatalf("missing=%v stale=%v", missing, stale)
	}
}

// Request bodies must not reach a required list through any $ref: a
// component shared with a response (Network, NodeInfo) would otherwise make
// generated clients send server-assigned fields.
func TestRequestBodiesReachNoRequiredFields(t *testing.T) {
	doc := openAPIDocument()
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	var walk func(at string, s any, seen map[string]bool)
	walk = func(at string, s any, seen map[string]bool) {
		switch v := s.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				name := strings.TrimPrefix(ref, "#/components/schemas/")
				if !seen[name] {
					seen[name] = true
					walk(at+" -> "+name, schemas[name], seen)
				}
				return
			}
			if req, ok := v["required"]; ok {
				t.Errorf("%s: required = %v", at, req)
			}
			for _, child := range v {
				walk(at, child, seen)
			}
		case []any:
			for _, child := range v {
				walk(at, child, seen)
			}
		}
	}
	for path, item := range doc["paths"].(map[string]any) {
		for method, op := range item.(map[string]any) {
			if body, ok := op.(map[string]any)["requestBody"]; ok {
				walk(strings.ToUpper(method)+" "+path, body.(map[string]any)["content"], map[string]bool{}) // the body itself is required
			}
		}
	}
}
