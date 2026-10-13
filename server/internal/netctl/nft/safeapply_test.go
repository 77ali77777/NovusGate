package nft

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeRunner records commands and answers "nft list" with the current table.
type fakeRunner struct {
	calls    []string
	applied  []string // scripts passed to `nft -f -`
	table    string   // what `nft list table` returns; "" means no table
	failNext map[string]error
}

func (f *fakeRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if err, ok := f.failNext[cmd]; ok {
		delete(f.failNext, cmd)
		return "boom", err
	}
	switch cmd {
	case "nft list table inet novusgate":
		if f.table == "" {
			return "Error: No such file or directory", errors.New("exit status 1")
		}
		return f.table, nil
	case "nft -f -":
		f.applied = append(f.applied, stdin)
	}
	return "", nil
}

type fakeTimer struct {
	armed    bool
	script   string
	failArm  error
	disarmed int
}

func (t *fakeTimer) Arm(script string, after time.Duration) error {
	if t.failArm != nil {
		return t.failArm
	}
	t.armed, t.script = true, script
	return nil
}

func (t *fakeTimer) Disarm() error { t.armed = false; t.disarmed++; return nil }

func newTestApplier(r *fakeRunner, tm *fakeTimer) (*SafeApplier, *func()) {
	var fire func()
	s := &SafeApplier{
		Exec:    Executor{Runner: r},
		Timer:   tm,
		Timeout: 60 * time.Second,
		Now:     func() time.Time { return testNow },
		AfterFunc: func(d time.Duration, f func()) func() bool {
			fire = f
			return func() bool { fire = nil; return true }
		},
	}
	return s, &fire
}

func TestSafeApplyRollsBackWithoutConfirmation(t *testing.T) {
	r := &fakeRunner{table: "table inet novusgate {\n}\n"}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", true)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || !p.Deadline.Equal(testNow.Add(60*time.Second)) {
		t.Fatalf("unexpected pending %+v", p)
	}
	if !tm.armed || !strings.HasPrefix(tm.script, removeTable) {
		t.Fatal("host timer must be armed with the snapshot before applying")
	}
	if _, err := s.Apply("OTHER", true); !errors.Is(err, ErrPendingConfirmation) {
		t.Fatalf("second apply must wait, got %v", err)
	}

	(*fire)() // timeout without confirmation

	if got := r.applied[len(r.applied)-1]; got != removeTable+"table inet novusgate {\n}\n" {
		t.Fatalf("rollback applied %q", got)
	}
	if tm.armed {
		t.Fatal("host timer must be disarmed after the in-process rollback")
	}
	if _, ok := s.PendingChange(); ok {
		t.Fatal("no change may stay pending after rollback")
	}
}

func TestSafeApplyConfirmKeepsChange(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", true)
	if err != nil {
		t.Fatal(err)
	}
	if tm.script != removeTable {
		t.Fatalf("snapshot of a missing table must remove it, got %q", tm.script)
	}
	if err := s.Confirm("wrong-id"); !errors.Is(err, ErrNoPending) {
		t.Fatalf("wrong id must be rejected, got %v", err)
	}
	if err := s.Confirm(p.ID); err != nil {
		t.Fatal(err)
	}
	if *fire != nil || tm.armed {
		t.Fatal("confirm must stop both timers")
	}
	if len(r.applied) != 1 || r.applied[0] != "NEW" {
		t.Fatalf("only the new ruleset may be applied, got %v", r.applied)
	}
}

func TestSafeApplyRefusesWithoutSafetyNet(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{failArm: errors.New("systemd-run missing")}
	s, _ := newTestApplier(r, tm)

	if _, err := s.Apply("NEW", true); err == nil {
		t.Fatal("apply must fail when the rollback timer cannot be armed")
	}
	if len(r.applied) != 0 {
		t.Fatal("nothing may be applied without the safety net")
	}
}

func TestSafeApplyCheckFailureChangesNothing(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{"nft -c -f -": errors.New("exit status 1")}}
	tm := &fakeTimer{}
	s, _ := newTestApplier(r, tm)

	if _, err := s.Apply("BROKEN", true); err == nil {
		t.Fatal("a ruleset rejected by nft -c must not be applied")
	}
	if len(r.applied) != 0 || tm.armed {
		t.Fatal("check failure must leave the host untouched")
	}
}

func TestSafeApplyFailedApplyDisarms(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{"nft -f -": errors.New("exit status 1")}}
	tm := &fakeTimer{}
	s, _ := newTestApplier(r, tm)

	if _, err := s.Apply("NEW", true); err == nil {
		t.Fatal("expected apply error")
	}
	if tm.armed || tm.disarmed != 1 {
		t.Fatal("a failed apply must disarm the host timer")
	}
	if _, ok := s.PendingChange(); ok {
		t.Fatal("a failed apply must not leave a pending change")
	}
}

func TestSafeApplyWithoutConfirmIsImmediate(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "" || *fire != nil || tm.armed {
		t.Fatal("unconfirmed mode must not arm timers")
	}
}

func TestSystemdTimerCommands(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{
		"systemctl stop novusgate-fw-rollback.timer": errors.New("exit status 5"),
	}}
	written := map[string]string{}
	tm := SystemdTimer{Runner: r, Unit: "novusgate-fw-rollback", Path: "/var/lib/novusgate/fw-rollback.nft",
		WriteFile: func(p, c string) error { written[p] = c; return nil }}

	// "boom" output is not "not loaded", so the stop failure is a real error.
	if err := tm.Arm("SNAP", 60*time.Second); err == nil {
		t.Fatal("a failing stop must abort Arm")
	}
	r.calls = nil
	if err := tm.Arm("SNAP", 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if written["/var/lib/novusgate/fw-rollback.nft"] != "SNAP" {
		t.Fatal("rollback script must be written before arming")
	}
	want := "systemd-run --unit=novusgate-fw-rollback --on-active=60s --timer-property=AccuracySec=1s nft -f /var/lib/novusgate/fw-rollback.nft"
	if r.calls[len(r.calls)-1] != want {
		t.Fatalf("got %q\nwant %q", r.calls[len(r.calls)-1], want)
	}
}
