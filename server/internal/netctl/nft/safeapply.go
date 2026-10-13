package nft

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	// ErrPendingConfirmation means an earlier change still waits for confirmation.
	ErrPendingConfirmation = errors.New("a firewall change is waiting for confirmation")
	// ErrNoPending means there is no change with that id to confirm.
	ErrNoPending = errors.New("no pending firewall change with this id")
)

// HostTimer restores a snapshot from outside the control plane, so a change
// that cuts off the operator is rolled back even if the process dies.
type HostTimer interface {
	Arm(rollbackScript string, after time.Duration) error
	Disarm() error
}

// Pending describes a change that is live but not yet confirmed.
type Pending struct {
	ID       string
	Deadline time.Time
}

// SafeApplier applies rulesets with an automatic rollback unless confirmed.
type SafeApplier struct {
	Exec      Executor
	Timer     HostTimer
	Timeout   time.Duration
	Now       func() time.Time
	AfterFunc func(d time.Duration, f func()) (stop func() bool)

	mu      sync.Mutex
	pending *pendingChange
}

type pendingChange struct {
	id       string
	snapshot string
	deadline time.Time
	stop     func() bool
}

// NewSafeApplier wires the real clock and timers.
func NewSafeApplier(exec Executor, timer HostTimer, timeout time.Duration) *SafeApplier {
	return &SafeApplier{
		Exec:    exec,
		Timer:   timer,
		Timeout: timeout,
		Now:     time.Now,
		AfterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
	}
}

// Apply validates and loads script. With confirm=false the change is final
// immediately (used by callers that cannot confirm, e.g. legacy endpoints);
// otherwise it stays pending and is rolled back after Timeout unless Confirm
// is called with the returned id.
func (s *SafeApplier) Apply(script string, confirm bool) (Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return Pending{}, ErrPendingConfirmation
	}
	if err := s.Exec.Check(script); err != nil {
		return Pending{}, err
	}
	if !confirm {
		return Pending{}, s.Exec.Apply(script)
	}
	snapshot, err := s.Exec.Snapshot()
	if err != nil {
		return Pending{}, err
	}
	// Never apply without the host-side safety net in place.
	if err := s.Timer.Arm(snapshot, s.Timeout); err != nil {
		return Pending{}, fmt.Errorf("arm rollback timer: %w", err)
	}
	if err := s.Exec.Apply(script); err != nil {
		if derr := s.Timer.Disarm(); derr != nil {
			log.Printf("firewall: disarm after failed apply: %v", derr)
		}
		return Pending{}, err
	}
	id := newID()
	p := &pendingChange{id: id, snapshot: snapshot, deadline: s.Now().Add(s.Timeout)}
	p.stop = s.AfterFunc(s.Timeout, func() { s.rollback(id) })
	s.pending = p
	return Pending{ID: id, Deadline: p.deadline}, nil
}

// Confirm makes the pending change permanent.
func (s *SafeApplier) Confirm(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.id != id {
		return ErrNoPending
	}
	s.pending.stop()
	s.pending = nil
	return s.Timer.Disarm()
}

// PendingChange reports the change waiting for confirmation, if any.
func (s *SafeApplier) PendingChange() (Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return Pending{}, false
	}
	return Pending{ID: s.pending.id, Deadline: s.pending.deadline}, true
}

func (s *SafeApplier) rollback(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.id != id {
		return
	}
	if err := s.Exec.Apply(s.pending.snapshot); err != nil {
		// The host timer is still armed and will retry the restore.
		log.Printf("firewall: rollback failed, host timer will restore: %v", err)
		s.pending = nil
		return
	}
	s.pending = nil
	if err := s.Timer.Disarm(); err != nil {
		log.Printf("firewall: disarm after rollback: %v", err)
	}
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// SystemdTimer arms a transient systemd timer on the host that loads the
// rollback script with nft after the timeout.
type SystemdTimer struct {
	Runner    Runner
	Unit      string // e.g. "novusgate-fw-rollback"
	Path      string // host path for the rollback script
	WriteFile func(path, content string) error
}

// Arm implements HostTimer.
func (t SystemdTimer) Arm(rollbackScript string, after time.Duration) error {
	if err := t.Disarm(); err != nil {
		return err
	}
	if err := t.WriteFile(t.Path, rollbackScript); err != nil {
		return err
	}
	secs := int(after / time.Second)
	if secs < 1 {
		secs = 1
	}
	out, err := t.Runner.Run("", "systemd-run",
		"--unit="+t.Unit,
		fmt.Sprintf("--on-active=%ds", secs),
		"--timer-property=AccuracySec=1s",
		"nft", "-f", t.Path)
	if err != nil {
		return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Disarm implements HostTimer. A timer that is not loaded is already disarmed.
func (t SystemdTimer) Disarm() error {
	out, err := t.Runner.Run("", "systemctl", "stop", t.Unit+".timer")
	if err != nil && !strings.Contains(out, "not loaded") {
		return fmt.Errorf("systemctl stop: %v: %s", err, strings.TrimSpace(out))
	}
	// Clear a failed transient unit so the next systemd-run can reuse the name;
	// "not loaded" just means there is nothing to clear.
	if out, err := t.Runner.Run("", "systemctl", "reset-failed", t.Unit+".service"); err != nil && !strings.Contains(out, "not loaded") {
		log.Printf("firewall: reset-failed %s: %v: %s", t.Unit, err, strings.TrimSpace(out))
	}
	return nil
}
