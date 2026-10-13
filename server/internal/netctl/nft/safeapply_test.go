package nft

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeRunner records commands; `nft list table` returns the current table.
type fakeRunner struct {
	calls    []string
	stdins   map[string]string // last stdin per command
	applied  []string          // scripts passed to `nft -f -`
	table    string            // what `nft list table` returns; "" means no table
	outputs  map[string]string // canned stdout per command
	failNext map[string]error
}

func (f *fakeRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if f.stdins == nil {
		f.stdins = map[string]string{}
	}
	f.stdins[cmd] = stdin
	if err, ok := f.failNext[cmd]; ok {
		delete(f.failNext, cmd)
		return f.outputs[cmd], err
	}
	switch cmd {
	case "nft list table inet novusgate":
		if f.table == "" {
			return "", errors.New("nft: exit status 1: Error: No such file or directory")
		}
		return f.table, nil
	case "nft -f -":
		f.applied = append(f.applied, stdin)
	}
	return f.outputs[cmd], nil
}

type fakeTimer struct {
	active     bool
	script     string
	after      time.Duration
	failArm    error
	failDisarm error
	disarmed   int
}

func (t *fakeTimer) Arm(script string, after time.Duration) error {
	if t.failArm != nil {
		return t.failArm
	}
	t.active, t.script, t.after = true, script, after
	return nil
}

func (t *fakeTimer) Disarm() error {
	if t.failDisarm != nil {
		return t.failDisarm
	}
	t.active = false
	t.disarmed++
	return nil
}

func (t *fakeTimer) Active() (bool, error) { return t.active, nil }

func newTestApplier(r *fakeRunner, tm *fakeTimer) (*SafeApplier, *func()) {
	var fire func()
	s := &SafeApplier{
		Exec:    Executor{Runner: r},
		Timer:   tm,
		Timeout: 60 * time.Second,
		Grace:   15 * time.Second,
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
	if !tm.active || !strings.HasPrefix(tm.script, removeTable) {
		t.Fatal("host timer must be armed with the snapshot before applying")
	}
	if tm.after != 75*time.Second {
		t.Fatalf("host timer must fire after timeout plus grace, got %v", tm.after)
	}
	if _, err := s.Apply("OTHER", true); !errors.Is(err, ErrPendingConfirmation) {
		t.Fatalf("second apply must wait, got %v", err)
	}

	(*fire)() // timeout without confirmation

	if got := r.applied[len(r.applied)-1]; got != removeTable+"table inet novusgate {\n}\n" {
		t.Fatalf("rollback applied %q", got)
	}
	if tm.active {
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
	if *fire != nil || tm.active {
		t.Fatal("confirm must stop both timers")
	}
	if len(r.applied) != 1 || r.applied[0] != "NEW" {
		t.Fatalf("only the new ruleset may be applied, got %v", r.applied)
	}
}

// After a restart the in-process state is gone, but the host rollback from
// the earlier unconfirmed change is still armed and must not be cancelled.
func TestSafeApplyRefusesWhileHostRollbackArmed(t *testing.T) {
	for _, confirm := range []bool{true, false} {
		r := &fakeRunner{}
		tm := &fakeTimer{active: true}
		s, _ := newTestApplier(r, tm)

		if _, err := s.Apply("NEW", confirm); !errors.Is(err, ErrRollbackArmed) {
			t.Fatalf("confirm=%v: got %v, want ErrRollbackArmed", confirm, err)
		}
		if len(r.applied) != 0 || tm.disarmed != 0 {
			t.Fatalf("confirm=%v: nothing may be applied or disarmed", confirm)
		}
	}
}

// If the host timer already restored the snapshot, confirming must not
// pretend the change is live.
func TestConfirmAfterHostRollbackReportsExpired(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", true)
	if err != nil {
		t.Fatal(err)
	}
	tm.active = false // the host timer fired

	if err := s.Confirm(p.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
	if _, ok := s.PendingChange(); ok || *fire != nil {
		t.Fatal("an expired change must be cleared and its in-process timer stopped")
	}
}

func TestConfirmKeepsPendingWhenDisarmFails(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", true)
	if err != nil {
		t.Fatal(err)
	}
	tm.failDisarm = errors.New("systemctl: bus error")

	if err := s.Confirm(p.ID); err == nil {
		t.Fatal("confirm must fail when the host timer cannot be disarmed")
	}
	if _, ok := s.PendingChange(); !ok || *fire == nil {
		t.Fatal("the change must stay pending so the rollback still happens")
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
	if len(r.applied) != 0 || tm.active {
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
	if tm.active || tm.disarmed != 1 {
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
	if p.ID != "" || *fire != nil || tm.active {
		t.Fatal("unconfirmed mode must not arm timers")
	}
}

const rollbackPath = "/var/lib/novusgate/fw-rollback.nft"

func newSystemdTimer(r *fakeRunner) SystemdTimer {
	return SystemdTimer{Runner: r, Unit: "novusgate-fw-rollback", Path: rollbackPath}
}

func TestSystemdTimerArmWritesOnHostAndSchedules(t *testing.T) {
	r := &fakeRunner{
		outputs:  map[string]string{"systemctl is-active novusgate-fw-rollback.timer": "inactive\n"},
		failNext: map[string]error{"systemctl is-active novusgate-fw-rollback.timer": errors.New("exit status 3")},
	}
	if err := newSystemdTimer(r).Arm("SNAP", 75*time.Second); err != nil {
		t.Fatal(err)
	}
	if r.stdins["tee "+rollbackPath] != "SNAP" {
		t.Fatal("the rollback script must be written through the host runner")
	}
	want := "systemd-run --unit=novusgate-fw-rollback --on-active=75s --timer-property=AccuracySec=1s nft -f " + rollbackPath
	if r.calls[len(r.calls)-1] != want {
		t.Fatalf("got %q\nwant %q", r.calls[len(r.calls)-1], want)
	}
}

func TestSystemdTimerRefusesWithoutHostNft(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{"nft --version": errors.New("nft: not found")}}
	if err := newSystemdTimer(r).Arm("SNAP", time.Minute); err == nil {
		t.Fatal("arming must fail when the host cannot run nft")
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "systemd-run") {
			t.Fatal("no timer may be created without host nft")
		}
	}
}

func TestSystemdTimerRefusesWhenAlreadyActive(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{"systemctl is-active novusgate-fw-rollback.timer": "active\n"}}
	if err := newSystemdTimer(r).Arm("SNAP", time.Minute); err == nil {
		t.Fatal("an armed rollback from an earlier change must not be replaced")
	}
}

func TestSystemdTimerActive(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{"systemctl is-active novusgate-fw-rollback.timer": "active\n"}}
	if ok, err := newSystemdTimer(r).Active(); err != nil || !ok {
		t.Fatalf("Active = %v, %v", ok, err)
	}
	r = &fakeRunner{
		outputs:  map[string]string{"systemctl is-active novusgate-fw-rollback.timer": "inactive\n"},
		failNext: map[string]error{"systemctl is-active novusgate-fw-rollback.timer": errors.New("exit status 3")},
	}
	if ok, err := newSystemdTimer(r).Active(); err != nil || ok {
		t.Fatalf("inactive timer: Active = %v, %v", ok, err)
	}
	r = &fakeRunner{failNext: map[string]error{"systemctl is-active novusgate-fw-rollback.timer": errors.New("bus error")}}
	if _, err := newSystemdTimer(r).Active(); err == nil {
		t.Fatal("an unknown systemctl failure must be an error, not 'inactive'")
	}
}
