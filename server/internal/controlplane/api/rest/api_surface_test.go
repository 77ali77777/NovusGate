package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveFull sends a request through the full HTTP handler (Router), which
// wraps the mux the way the server does.
func serveFull(s *Server, method, path string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	req.RemoteAddr = "198.51.100.200:5555"
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

func TestHeadIsServedAsGet(t *testing.T) {
	s, _, _ := newContractServer(t)
	for _, c := range []struct {
		path string
		auth bool
	}{{"/health", false}, {"/api/v1/networks", true}} {
		rec := serveFull(s, "HEAD", c.path, c.auth)
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Errorf("HEAD %s = %d with %d body bytes, want 200 and no body", c.path, rec.Code, rec.Body.Len())
		}
	}
}

func TestAPIPathEdgesAreJSON404(t *testing.T) {
	s, _, _ := newContractServer(t)
	for _, p := range []string{"/api", "/api/v1/networks/"} {
		rec := serveFull(s, "GET", p, true)
		if rec.Code != http.StatusNotFound || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("GET %s = %d %q, want a JSON 404", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

func TestPathCleaningRedirectIsLogged(t *testing.T) {
	logs := captureLogs(t)
	s, _, _ := newContractServer(t)
	rec := serveFull(s, "GET", "/api/v1//networks", true)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("unclean path = %d, want mux's 301", rec.Code)
	}
	if !strings.Contains(logs.String(), `"status":301`) {
		t.Fatalf("the 301 must be in the request log:\n%s", logs)
	}
}

func TestDocExtraResponsesNameDocOps(t *testing.T) {
	known := map[string]bool{}
	for _, op := range docOps {
		known[op.Method+" "+op.Path] = true
	}
	for key := range docExtraResponses {
		if !known[key] {
			t.Errorf("docExtraResponses key %q names no docOps entry", key)
		}
	}
	for key := range docQueryParams {
		if !known[key] {
			t.Errorf("docQueryParams key %q names no docOps entry", key)
		}
	}
}

func TestOpenAPIDetails(t *testing.T) {
	raw, _ := json.Marshal(openAPIDocument())
	var doc struct {
		Components struct {
			Schemas         map[string]map[string]any `json:"schemas"`
			SecuritySchemes map[string]map[string]any `json:"securitySchemes"`
		} `json:"components"`
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Components.SecuritySchemes["apiKey"]["in"] != "header" || doc.Components.SecuritySchemes["apiKey"]["name"] != "X-API-Key" {
		t.Errorf("X-API-Key security scheme = %v", doc.Components.SecuritySchemes["apiKey"])
	}
	hasQuery := func(path, method, name string) bool {
		for _, p := range doc.Paths[path][method].Parameters {
			if p.Name == name && p.In == "query" {
				return true
			}
		}
		return false
	}
	for _, c := range [][3]string{
		{"/api/v1/system/fail2ban/logs", "get", "lines"},
		{"/api/v1/system/fail2ban/ban-history", "get", "limit"},
		{"/api/v1/firewall/v2/services", "post", "confirm"},
	} {
		if !hasQuery(c[0], c[1], c[2]) {
			t.Errorf("%s %s lacks query parameter %s", c[1], c[0], c[2])
		}
	}
	png := doc.Paths["/api/v1/nodes/{id}/qrcode"]["get"].Responses["200"].Content["image/png"].Schema
	if png["format"] != "binary" {
		t.Errorf("qrcode schema = %v, want format binary", png)
	}
	node := doc.Components.Schemas["Node"]["properties"].(map[string]any)
	if enum, _ := node["status"].(map[string]any)["enum"].([]any); len(enum) != 4 {
		t.Errorf("Node.status = %v, want an enum of 4 statuses", node["status"])
	}
	state := doc.Components.Schemas["V2StateResponse"]["properties"].(map[string]any)
	for _, f := range []string{"ssh_ports", "egress_interface"} {
		if state[f].(map[string]any)["nullable"] == true {
			t.Errorf("V2StateResponse.%s is never null when present", f)
		}
	}
	for name, schema := range doc.Components.Schemas {
		for prop, v := range schema["properties"].(map[string]any) {
			m := v.(map[string]any)
			if _, ok := m["allOf"]; ok && m["nullable"] == true && m["type"] != "object" {
				t.Errorf("%s.%s: nullable allOf needs type object for strict 3.0.3 validators", name, prop)
			}
		}
	}
}
