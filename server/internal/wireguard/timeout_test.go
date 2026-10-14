package wireguard

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A wg command that hangs must not hang its caller (the reconciler tick).
func TestCommandsTimeOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "wg")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	orig := commandTimeout
	t.Cleanup(func() { commandTimeout = orig })
	commandTimeout = 200 * time.Millisecond

	start := time.Now()
	if _, err := NewManager("wg-test").GetPeers(); err == nil {
		t.Fatal("a hanging wg must be an error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("GetPeers took %s, want it cut at the timeout", d)
	}
}
