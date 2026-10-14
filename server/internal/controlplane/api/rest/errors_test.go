package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorBodyIsUnified(t *testing.T) {
	cases := map[int]string{
		400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
		405: "method_not_allowed", 409: "conflict", 410: "gone", 500: "internal_error",
		502: "bad_gateway", 503: "unavailable", 418: "error",
	}
	for status, code := range cases {
		rec := httptest.NewRecorder()
		errorResponse(rec, status, "something <went> wrong")
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%d: body %q is not the unified shape: %v", status, rec.Body, err)
		}
		if rec.Code != status || body.Error.Code != code || body.Error.Message != "something <went> wrong" {
			t.Errorf("%d: got status %d, code %q, message %q", status, rec.Code, body.Error.Code, body.Error.Message)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%d: content type %q", status, rec.Header().Get("Content-Type"))
		}
	}
	rec := httptest.NewRecorder()
	errorWithCode(rec, http.StatusConflict, "cidr_overlap", "overlaps")
	if rec.Code != 409 || rec.Body.String() != `{"error":{"code":"cidr_overlap","message":"overlaps"}}`+"\n" {
		t.Fatalf("errorWithCode = %d %q", rec.Code, rec.Body)
	}
}
