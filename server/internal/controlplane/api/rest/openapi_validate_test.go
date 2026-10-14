package rest

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// validateSchema checks a decoded JSON value against the subset of OpenAPI
// 3.0 the generator emits: type, properties, required, items,
// additionalProperties, nullable, $ref and a single-element allOf.
func validateSchema(schema map[string]any, v any, schemas map[string]any, at string) []string {
	if ref, ok := schema["$ref"].(string); ok {
		return validateSchema(schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), v, schemas, at)
	}
	if all, ok := schema["allOf"].([]any); ok && len(all) == 1 {
		if v == nil && schema["nullable"] == true {
			return nil
		}
		return validateSchema(all[0].(map[string]any), v, schemas, at)
	}
	if v == nil {
		if schema["nullable"] == true || len(schema) == 0 {
			return nil
		}
		return []string{at + ": null is not allowed"}
	}
	var errs []string
	switch schema["type"] {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			return []string{at + ": want object"}
		}
		props, _ := schema["properties"].(map[string]any)
		if req, ok := schema["required"].([]string); ok {
			for _, k := range req {
				if _, ok := obj[k]; !ok {
					errs = append(errs, at+"."+k+": required")
				}
			}
		}
		for k, val := range obj {
			if ps, ok := props[k].(map[string]any); ok {
				errs = append(errs, validateSchema(ps, val, schemas, at+"."+k)...)
			} else if ap, ok := schema["additionalProperties"].(map[string]any); ok {
				errs = append(errs, validateSchema(ap, val, schemas, at+"."+k)...)
			} else if props != nil {
				errs = append(errs, at+"."+k+": not in the schema")
			}
		}
	case "array":
		arr, ok := v.([]any)
		if !ok {
			return []string{at + ": want array"}
		}
		items, _ := schema["items"].(map[string]any)
		for i, e := range arr {
			errs = append(errs, validateSchema(items, e, schemas, at+"["+strconv.Itoa(i)+"]")...)
		}
	case "string":
		if _, ok := v.(string); !ok {
			errs = append(errs, at+": want string")
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			errs = append(errs, at+": want boolean")
		}
	case "integer":
		if f, ok := v.(float64); !ok || f != math.Trunc(f) {
			errs = append(errs, at+": want integer")
		}
	case "number":
		if _, ok := v.(float64); !ok {
			errs = append(errs, at+": want number")
		}
	}
	return errs
}

// assertMatchesSpec finds the documented operation for the request and
// checks the response's status and JSON body against it.
func assertMatchesSpec(t *testing.T, s *Server, method, path string, rec *httptest.ResponseRecorder) {
	t.Helper()
	var match mux.RouteMatch
	if !s.router.Match(httptest.NewRequest(method, path, nil), &match) || match.Route == nil {
		t.Errorf("%s %s: no route", method, path)
		return
	}
	tpl, _ := match.Route.GetPathTemplate()
	if name := match.Route.GetName(); name == "api-fallback" || name == "spa" {
		tpl = "" // only the error body is checked below
	}
	doc := openAPIDocument()
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	var body any
	isJSON := strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json")
	if isJSON && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("%s %s: invalid JSON: %v", method, path, err)
			return
		}
	}
	if rec.Code >= 400 {
		if errs := validateSchema(map[string]any{"$ref": "#/components/schemas/Error"}, body, schemas, "body"); len(errs) > 0 {
			t.Errorf("%s %s %d: error body does not match Error: %v", method, path, rec.Code, errs)
		}
		return
	}
	for _, op := range docOps {
		if op.Method != method || op.Path != tpl {
			continue
		}
		response := op.Response
		if op.Status != rec.Code {
			extra, ok := docExtraResponses[method+" "+tpl][rec.Code]
			if !ok {
				t.Errorf("%s %s: status %d, documented %d", method, tpl, rec.Code, op.Status)
				return
			}
			response = extra
		}
		switch response.(type) {
		case nil, mediaType:
			return
		}
		g := &schemaGen{components: map[string]any{}}
		schema := g.schema(response)
		for k, v := range g.components {
			schemas[k] = v
		}
		if errs := validateSchema(schema, body, schemas, "body"); len(errs) > 0 {
			t.Errorf("%s %s: response does not match the documented schema:\n%s", method, tpl, strings.Join(errs, "\n"))
		}
		return
	}
	t.Errorf("%s %s: undocumented operation", method, tpl)
}

func TestValidateSchemaCatchesMismatches(t *testing.T) {
	schemas := map[string]any{"N": map[string]any{"type": "object", "required": []string{"id"},
		"properties": map[string]any{"id": map[string]any{"type": "string"}, "port": map[string]any{"type": "integer"}}}}
	ref := map[string]any{"$ref": "#/components/schemas/N"}
	var good, bad any
	json.Unmarshal([]byte(`{"id":"a","port":51820}`), &good)
	json.Unmarshal([]byte(`{"port":"x","extra":1}`), &bad)
	if errs := validateSchema(ref, good, schemas, "b"); len(errs) != 0 {
		t.Fatalf("valid body rejected: %v", errs)
	}
	if errs := validateSchema(ref, bad, schemas, "b"); len(errs) != 3 {
		t.Fatalf("want 3 errors (missing id, port type, extra field), got %v", errs)
	}
}
