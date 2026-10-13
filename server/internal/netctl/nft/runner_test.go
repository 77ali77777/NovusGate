package nft

import (
	"strings"
	"testing"
)

// A warning on stderr must never end up in parsed output such as a snapshot.
func TestRunSeparatesStdoutAndStderr(t *testing.T) {
	out, err := run("", "sh", "-c", "echo out; echo warn >&2")
	if err != nil || out != "out\n" {
		t.Fatalf("run = %q, %v; want stdout only", out, err)
	}
	out, err = run("", "sh", "-c", "echo partial; echo boom >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("a failing command must report its stderr, got %v", err)
	}
	if out != "partial\n" {
		t.Fatalf("stdout must still be returned on failure, got %q", out)
	}
}
