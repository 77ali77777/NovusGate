package firewall

import (
	"testing"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// The container's nft (Alpine) can be older than the host kernel: nft
// 1.0.9 segfaults even on "nft list ruleset" under kernel 7.0 (Ubuntu
// 26.04), where the host's nft 1.1.6 works. Check, apply, snapshot and the
// live readers must use the host's nft, the same one the boot unit and the
// rollback timer run (CheckHost already requires it in nft mode).
func TestHostEngineRunsTheHostsNft(t *testing.T) {
	e := NewHostEngine(ModeNft, nil)
	if _, ok := e.Applier.Exec.Runner.(nft.NsenterRunner); !ok {
		t.Fatalf("nft runner = %T, want nft.NsenterRunner (the host's nft)", e.Applier.Exec.Runner)
	}
}
