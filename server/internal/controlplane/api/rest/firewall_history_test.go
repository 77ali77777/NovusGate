package rest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
)

func newHistoryServer(t *testing.T) *Server {
	t.Helper()
	s, _ := newEngineServer(t, firewall.ModeNft)
	db, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("DELETE FROM fw_history"); err != nil {
		t.Fatal(err)
	}
	s.firewall.History = s.store
	return s
}

func historyEntries(t *testing.T, s *Server) []V2HistoryEntry {
	t.Helper()
	rec := callAs(t, s, "GET", "/api/v1/firewall/v2/history", "", true)
	if rec.Code != 200 {
		t.Fatalf("history = %d %s", rec.Code, rec.Body)
	}
	var got V2HistoryResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	return got.Entries
}

func TestFirewallHistoryAndRestore(t *testing.T) {
	s := newHistoryServer(t)
	for _, port := range []string{"9100", "9200"} {
		rec := callAs(t, s, "POST", "/api/v1/firewall/v2/services?confirm=false", `{"protocol":"tcp","port_from":`+port+`}`, true)
		if rec.Code != 200 {
			t.Fatalf("create %s = %d %s", port, rec.Code, rec.Body)
		}
	}
	got := historyEntries(t, s)
	if len(got) != 3 || got[2].Action != "baseline" || got[0].Username != "engine-admin" ||
		got[0].Action != "POST /api/v1/firewall/v2/services" ||
		strings.Join(got[0].Added, "|") != "service tcp 9200 from any" || len(got[0].Removed) != 0 ||
		strings.Join(got[1].Added, "|") != "service tcp 9100 from any" {
		t.Fatalf("history = %+v", got)
	}
	rec := callAs(t, s, "GET", "/api/v1/firewall/v2/history", "", true)
	assertMatchesSpec(t, s, "GET", "/api/v1/firewall/v2/history", rec)

	// Back to the state with only 9100.
	rec = callAs(t, s, "POST", "/api/v1/firewall/v2/history/"+got[1].ID+"/restore?confirm=false", "", true)
	if rec.Code != 200 {
		t.Fatalf("restore = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "POST", "/api/v1/firewall/v2/history/{id}/restore", rec)
	st, _ := s.firewall.LoadState(context.Background())
	if len(st.Services) != 1 || st.Services[0].PortFrom != 9100 {
		t.Fatalf("restored services = %+v", st.Services)
	}
	got = historyEntries(t, s)
	if len(got) != 4 || !strings.HasPrefix(got[0].Action, "restore ") ||
		strings.Join(got[0].Removed, "|") != "service tcp 9200 from any" || len(got[0].Added) != 0 {
		t.Fatalf("after restore = %+v", got[0])
	}

	if rec := callAs(t, s, "POST", "/api/v1/firewall/v2/history/00000000-0000-0000-0000-000000000000/restore", "", true); rec.Code != 404 {
		t.Fatalf("unknown entry = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "POST", "/api/v1/firewall/v2/history/not-a-uuid/restore", "", true); rec.Code != 404 {
		t.Fatalf("bad id = %d %s", rec.Code, rec.Body)
	}
}

// Without the nft engine there is no history.
func TestFirewallHistoryNeedsTheEngine(t *testing.T) {
	s, _, _ := newContractServer(t)
	if rec := callAs(t, s, "GET", "/api/v1/firewall/v2/history", "", true); rec.Code != 409 {
		t.Fatalf("history = %d %s", rec.Code, rec.Body)
	}
}
