package wireguard

import (
	"errors"
	"strings"
	"testing"
)

// Ubuntu 26.04 confines /usr/bin/wg-quick and /usr/bin/wg with AppArmor
// profiles that attach by path, also to the container's copies: the
// container's wg-quick then may not run its own busybox readlink and every
// network made from the panel stayed down. WireGuard therefore runs on the
// host: its own tools under its own profiles, its interfaces as systemd
// units (wg-quick@wgN) like wg0, so they come back after a reboot or a
// container restart.

// hostRun fakes the host: it answers commands from a table and records them.
type hostRun struct {
	calls []string
	out   map[string]string
	fail  map[string]bool
}

func (h *hostRun) run(name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	h.calls = append(h.calls, cmd)
	if h.fail[cmd] {
		return h.out[cmd], errors.New("exit status 1")
	}
	return h.out[cmd], nil
}

func fakeHost(t *testing.T, exists bool) *hostRun {
	t.Helper()
	h := &hostRun{out: map[string]string{}, fail: map[string]bool{}}
	origRun, origExists := run, interfaceExists
	run = h.run
	interfaceExists = func(string) bool { return exists }
	t.Cleanup(func() { run, interfaceExists = origRun, origExists })
	return h
}

func TestCommandsRunOnTheHost(t *testing.T) {
	cmd, cancel := command("wg", "show", "wg1", "dump")
	defer cancel()
	want := "nsenter -t 1 -m -u -i -n -- wg show wg1 dump"
	if got := strings.Join(cmd.Args, " "); got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestUpStartsTheSystemdUnit(t *testing.T) {
	h := fakeHost(t, false)
	if err := NewManager("wg3").Up(); err != nil {
		t.Fatal(err)
	}
	want := "systemctl enable wg-quick@wg3\nsystemctl start wg-quick@wg3"
	if got := strings.Join(h.calls, "\n"); got != want {
		t.Fatalf("calls:\n%s\nwant:\n%s", got, want)
	}
}

// Up already: only made sure it comes back at boot.
func TestUpLeavesARunningUnit(t *testing.T) {
	h := fakeHost(t, true)
	if err := NewManager("wg3").Up(); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.calls {
		if strings.Contains(c, "start") || strings.Contains(c, "down") {
			t.Fatalf("a running unit must not be touched: %v", h.calls)
		}
	}
}

// Brought up outside systemd (by hand, or by an older version from the
// container): handed over to the unit, else the unit fails "already exists".
func TestUpHandsAManualInterfaceToSystemd(t *testing.T) {
	h := fakeHost(t, true)
	h.fail["systemctl is-active --quiet wg-quick@wg3"] = true
	if err := NewManager("wg3").Up(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(h.calls, "\n")
	if !strings.Contains(got, "wg-quick down wg3\nsystemctl start wg-quick@wg3") {
		t.Fatalf("calls:\n%s", got)
	}
}

// A unit that does not start says why (its journal), not just "failed".
func TestUpReportsTheUnitsJournal(t *testing.T) {
	h := fakeHost(t, false)
	h.fail["systemctl start wg-quick@wg3"] = true
	h.out["journalctl -u wg-quick@wg3 -n 5 --no-pager -o cat"] = "RTNETLINK answers: Address already in use"
	err := NewManager("wg3").Up()
	if err == nil || !strings.Contains(err.Error(), "Address already in use") {
		t.Fatalf("err = %v, want the journal's reason", err)
	}
}

// A new config takes effect through a restart of the unit.
func TestRestartAppliesANewConfig(t *testing.T) {
	h := fakeHost(t, true)
	if err := NewManager("wg3").Restart(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.calls, "\n"); !strings.Contains(got, "systemctl restart wg-quick@wg3") {
		t.Fatalf("calls:\n%s", got)
	}
}

// Down stops the unit for good; an interface left behind is removed.
func TestDownDisablesTheUnit(t *testing.T) {
	h := fakeHost(t, true)
	if err := NewManager("wg3").Down(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(h.calls, "\n")
	if !strings.Contains(got, "systemctl disable --now wg-quick@wg3") || !strings.Contains(got, "ip link delete wg3") {
		t.Fatalf("calls:\n%s", got)
	}
}

// The host needs its own wireguard-tools.
func TestInitNeedsTheHostsTools(t *testing.T) {
	h := fakeHost(t, false)
	h.fail["wg --version"] = true
	if err := NewManager("wg3").Init(); err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("Init = %v, want an error naming the host", err)
	}
}

// Keys are made in Go (Curve25519, as wg does), so no wg binary and no
// AppArmor profile is involved. Vector from wg genkey / wg pubkey.
func TestPublicKeyMatchesWg(t *testing.T) {
	pub, err := PublicKey("AOi1iYCVAKKrEq19mcwp7Kf7jn2L4nmlGKm1sBPTKkc=")
	if err != nil || pub != "4CT7TNRf8GQVhqvzBNNpT2jjbP8DqAk5f9fwbWkh4nM=" {
		t.Fatalf("PublicKey = %q, %v", pub, err)
	}
	if _, err := PublicKey("not-a-key"); err == nil {
		t.Fatal("a malformed key must be an error")
	}
	priv, pub, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := PublicKey(priv); again != pub || len(priv) != 44 {
		t.Fatalf("GenerateKeys pair does not match: %q %q", priv, pub)
	}
}
