package nft

import (
	"os"
	"path/filepath"
	"testing"
)

// testdata/live.txt and live.json are real `nft -a list` and `nft -j list`
// output (nft 1.0.6) of full.nft with one dropped source per family added;
// two counters in live.txt were edited to non-zero values.

func TestParseCounters(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("testdata", "live.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := ParseCounters(string(text))
	if len(got) != 12 {
		t.Fatalf("got %d counters: %+v", len(got), got)
	}
	want := RuleCounter{Chain: "input", Rule: "ip saddr @blocked_v4 drop", Packets: 3, Bytes: 180}
	if got[0] != want {
		t.Fatalf("first = %+v, want %+v", got[0], want)
	}
	var def *RuleCounter
	for i := range got {
		if got[i].Comment == "default drop" {
			def = &got[i]
		}
	}
	if def == nil || def.Chain != "input" || def.Rule != "" || def.Packets != 12 || def.Bytes != 840 {
		t.Fatalf("default drop = %+v", def)
	}
	last := got[len(got)-1]
	if last.Chain != "vpn_policy" || last.Comment != "vpn default drop" || last.Rule != "drop" {
		t.Fatalf("last = %+v", last)
	}
}

func TestParseDropped(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("testdata", "live.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDropped(js)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Address != "198.51.100.77" || got[1].Address != "2001:db8::99" {
		t.Fatalf("got %+v", got)
	}
	// timeout 3600 s, expires 3599 s: seen one second ago.
	if got[0].SecondsAgo != 1 {
		t.Fatalf("seconds ago = %d", got[0].SecondsAgo)
	}
	if _, err := ParseDropped([]byte("not json")); err == nil {
		t.Fatal("bad JSON must fail")
	}
	// A table without the sets (older ruleset) is not an error.
	if got, err := ParseDropped([]byte(`{"nftables":[{"table":{"family":"inet","name":"novusgate"}}]}`)); err != nil || len(got) != 0 {
		t.Fatalf("no sets = %v %v", got, err)
	}
}
