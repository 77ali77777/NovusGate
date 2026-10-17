package rest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/wireguard"
)

// loadNetworks against fake wg tools: it imports an unknown live peer,
// restores a missing DB peer, and skips (with a warning) an interface
// whose peers cannot be read.
func TestLoadNetworksImportsRestoresAndSurvivesErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	logs := captureLogs(t)
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)

	dir := t.TempDir()
	wgLog := filepath.Join(dir, "wg.log")
	unknown := strings.Repeat("U", 43) + "="
	scripts := map[string]string{
		"wg-quick": "#!/bin/sh\nexit 0\n",
		"wg": `#!/bin/sh
if [ "$1" = show ] && [ "$3" = dump ]; then
  case "$2" in
    wg66) printf 'priv\tpub\t51866\toff\n` + unknown + `\t(none)\t203.0.113.9:4000\t10.66.0.50/32\t0\t0\t0\toff\n'; exit 0 ;;
    *) echo "interface $2 down" >&2; exit 1 ;;
  esac
fi
echo "$*" >> "` + wgLog + `"
`,
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	wireguard.SetHostTools(false) // the fake wg on PATH, not the host's
	origDelay, origBring := loadNetworksDelay, wgBringUp
	t.Cleanup(func() { loadNetworksDelay, wgBringUp = origDelay, origBring; wireguard.SetHostTools(true) })
	loadNetworksDelay = 0
	wgInit = func(*wireguard.Manager) error { return nil } // newContractServer restores it
	// The interfaces "come up" (their systemd units are the host's); the
	// peers are then restored and imported through the fake wg.
	wgBringUp = func(*wireguard.Manager, bool) error { return nil }

	s.loadNetworks()

	calls, _ := os.ReadFile(wgLog)
	if want := "set wg66 peer " + seed.node.PublicKey + " allowed-ips 10.66.0.3/32"; !strings.Contains(string(calls), want) {
		t.Errorf("the missing DB peer must be restored; wg calls:\n%s", calls)
	}
	nodes, err := st.ListNodes(context.Background(), seed.network.ID)
	if err != nil {
		t.Fatal(err)
	}
	imported := false
	for _, n := range nodes {
		if n.PublicKey == unknown && n.VirtualIP.String() == "10.66.0.50" {
			imported = true
		}
	}
	if !imported {
		t.Errorf("the unknown live peer must be imported into the database")
	}
	if !strings.Contains(logs.String(), "cannot read peers of wg68") {
		t.Errorf("an unreadable interface must be skipped with a warning:\n%s", logs)
	}
}
