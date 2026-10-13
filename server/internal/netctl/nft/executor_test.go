package nft

import (
	"os"
	"strings"
	"testing"
)

// TestExecutorRoundTripInKernel applies a ruleset, snapshots it, replaces it
// and restores the snapshot through the real nft binary. NFT_CHECK=1 only.
func TestExecutorRoundTripInKernel(t *testing.T) {
	if os.Getenv("NFT_CHECK") != "1" {
		t.Skip("set NFT_CHECK=1 to run against the kernel")
	}
	e := Executor{Runner: HostRunner{}}

	first, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(first); err != nil {
		t.Fatal(err)
	}
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	second := fullRuleset()
	second.Blocked = nil
	second.Services = nil
	secondScript, err := Compile(second, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(secondScript); err != nil {
		t.Fatal(err)
	}
	if err := e.Check(snap); err != nil {
		t.Fatalf("snapshot must be a valid script: %v", err)
	}
	if err := e.Apply(snap); err != nil {
		t.Fatal(err)
	}
	listed, err := HostRunner{}.Run("", "nft", "list", "set", "inet", TableName, "blocked_v4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed, "198.51.100.0/24") {
		t.Fatalf("restore lost blocked entries:\n%s", listed)
	}

	// Removing the table through the empty-host snapshot.
	if err := e.Apply(removeTable); err != nil {
		t.Fatal(err)
	}
	if s, err := e.Snapshot(); err != nil || s != removeTable {
		t.Fatalf("missing table must snapshot as removal, got %q, %v", s, err)
	}
}
