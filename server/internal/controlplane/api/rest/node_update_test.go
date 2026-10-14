package rest

import (
	"context"
	"testing"
)

func TestUpdateNodeValidatesInput(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	path := "/api/v1/nodes/" + seed.node.ID
	for body, code := range map[string]string{
		`{"status":"banana"}`:            "invalid_status",
		`{"expires_at":"next tuesday"}`: "invalid_expires_at",
	} {
		rec := callAs(t, s, "PUT", path, body, true)
		if rec.Code != 400 || errorCode(t, rec.Body.Bytes()) != code {
			t.Errorf("%s = %d %s, want 400 %s", body, rec.Code, rec.Body, code)
		}
	}
	// What the web sends today must keep working.
	for _, body := range []string{
		`{"status":"offline"}`,
		`{"expires_at":"2099-10-14T12:00:00.000Z"}`, // Date.toISOString()
		`{"expires_at":""}`,                          // remove the expiry
		`{"name":"contract-node-x"}`,
	} {
		if rec := callAs(t, s, "PUT", path, body, true); rec.Code != 200 {
			t.Errorf("%s = %d %s, want 200", body, rec.Code, rec.Body)
		}
	}
	n, _ := st.GetNode(context.Background(), seed.node.ID)
	if n.Status != "offline" {
		t.Fatalf("a rejected update must not be stored; status = %s", n.Status)
	}
}
