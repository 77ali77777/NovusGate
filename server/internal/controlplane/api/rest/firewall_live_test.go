package rest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
)

func fakeProc(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "sys/net/netfilter")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "nf_conntrack_count"), []byte("3\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "nf_conntrack_max"), []byte("65536\n"), 0o644)
	orig := conntrackRoot
	conntrackRoot = root
	t.Cleanup(func() { conntrackRoot = orig })
}

func TestFirewallLive(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeNft)
	fakeProc(t)
	rec := callAs(t, s, "GET", "/api/v1/firewall/v2/live", "", true)
	if rec.Code != 200 {
		t.Fatalf("live = %d %s", rec.Code, rec.Body)
	}
	var got V2LiveResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Mode != firewall.ModeNft || !got.TableLoaded || len(got.Counters) != 1 || got.Counters[0].Packets != 9 ||
		len(got.Dropped) != 1 || got.Dropped[0].SecondsAgo != 60 || got.Conntrack.Count != 3 || got.Conntrack.Max != 65536 {
		t.Fatalf("live = %s", rec.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/firewall/v2/live", rec)
}

// Without the nft engine (iptables mode) there is no table, but conntrack
// is still shown.
func TestFirewallLiveWithoutEngine(t *testing.T) {
	s, _, _ := newContractServer(t)
	fakeProc(t)
	rec := callAs(t, s, "GET", "/api/v1/firewall/v2/live", "", true)
	var got V2LiveResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got.Mode != firewall.ModeIptables || got.TableLoaded || got.Counters == nil || got.Conntrack.Count != 3 {
		t.Fatalf("live = %d %s", rec.Code, rec.Body)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/firewall/v2/live", rec)
}
