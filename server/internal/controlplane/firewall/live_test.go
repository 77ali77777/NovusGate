package firewall

import (
	"errors"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// liveRunner answers the two listings Live runs.
type liveRunner struct {
	text, js string
	err      error
	calls    []string
}

func (r *liveRunner) Run(_ string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, cmd)
	if r.err != nil {
		return "", r.err
	}
	switch cmd {
	case "nft -a list table inet novusgate":
		return r.text, nil
	case "nft -j list table inet novusgate":
		return r.js, nil
	}
	return "", errors.New("unexpected " + cmd)
}

func liveEngine(r nft.Runner) *Engine {
	return &Engine{Mode: ModeNft, Applier: &nft.SafeApplier{Exec: nft.Executor{Runner: r}}}
}

func TestLiveReadsCountersAndDroppedSources(t *testing.T) {
	r := &liveRunner{
		text: "table inet novusgate { # handle 2\n\tchain input { # handle 1\n" +
			"\t\tcounter packets 5 bytes 300 comment \"default drop\" # handle 36\n\t}\n}\n",
		js: `{"nftables":[{"set":{"family":"inet","name":"dropped_v4","table":"novusgate","type":"ipv4_addr","timeout":3600,` +
			`"elem":[{"elem":{"val":"203.0.113.9","expires":3000}}]}}]}`,
	}
	live, err := liveEngine(r).Live()
	if err != nil {
		t.Fatal(err)
	}
	if !live.TableLoaded || len(live.Counters) != 1 || live.Counters[0].Packets != 5 ||
		len(live.Dropped) != 1 || live.Dropped[0].Address != "203.0.113.9" || live.Dropped[0].SecondsAgo != 600 {
		t.Fatalf("live = %+v", live)
	}
}

// iptables and shadow modes have no table: that is a state, not an error.
func TestLiveWithoutTable(t *testing.T) {
	r := &liveRunner{err: errors.New("nft: exit status 1: Error: No such file or directory; did you mean table 'novusgate' in family inet?")}
	live, err := liveEngine(r).Live()
	if err != nil || live.TableLoaded || live.Counters != nil {
		t.Fatalf("live = %+v err %v", live, err)
	}
	r = &liveRunner{err: errors.New("nft: permission denied")}
	if _, err := liveEngine(r).Live(); err == nil {
		t.Fatal("other nft errors must be returned")
	}
}
