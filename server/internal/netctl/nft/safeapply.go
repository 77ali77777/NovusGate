package nft

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"
)

var (
	// ErrPendingConfirmation means an earlier change still waits for confirmation.
	ErrPendingConfirmation = errors.New("a firewall change is waiting for confirmation")
	// ErrNoPending means there is no change with that id to confirm.
	ErrNoPending = errors.New("no pending firewall change with this id")
	// ErrRollbackArmed means a host rollback from an earlier, unconfirmed
	// change (possibly before a restart) is still scheduled.
	ErrRollbackArmed = errors.New("a rollback from an earlier unconfirmed firewall change is still armed")
	// ErrExpired means the change was already rolled back before confirmation.
	ErrExpired = errors.New("the firewall change expired and was rolled back")
)

// HostTimer restores a snapshot from outside the control plane, so a change
// that cuts off the operator is rolled back even if the process dies.
type HostTimer interface {
	Arm(rollbackScript string, after time.Duration) error
	Disarm() error
	Active() (bool, error)
}

// Pending describes a change that is live but not yet confirmed.
type Pending struct {
	ID       string
	Deadline time.Time
}

// SafeApplier applies rulesets with an automatic rollback unless confirmed.
// The in-process timer fires at Timeout; the host timer at Timeout+Grace, so
// the process normally rolls back first and the host only covers a crash.
type SafeApplier struct {
	Exec      Executor
	Timer     HostTimer
	Timeout   time.Duration
	Grace     time.Duration
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
		Grace:   15 * time.Second,
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
	// A rollback armed before a restart would overwrite any new change.
	armed, err := s.Timer.Active()
	if err != nil {
		return Pending{}, fmt.Errorf("check rollback timer: %w", err)
	}
	if armed {
		return Pending{}, ErrRollbackArmed
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
	if err := s.Timer.Arm(snapshot, s.Timeout+s.Grace); err != nil {
		return Pending{}, fmt.Errorf("arm rollback timer: %w", err)
	}
	if err := s.Exec.Apply(script); err != nil {
		if derr := s.Timer.Disarm(); derr != nil {
			slog.Error(fmt.Sprintf("firewall: disarm after failed apply: %v", derr))
		}
		return Pending{}, err
	}
	id := newID()
	p := &pendingChange{id: id, snapshot: snapshot, deadline: s.Now().Add(s.Timeout)}
	p.stop = s.AfterFunc(s.Timeout, func() { s.rollback(id) })
	s.pending = p
	return Pending{ID: id, Deadline: p.deadline}, nil
}

// Confirm makes the pending change permanent. It fails with ErrExpired when
// the host already rolled the change back, and keeps the change pending when
// the host timer cannot be disarmed, so the rollback still happens.
func (s *SafeApplier) Confirm(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.id != id {
		return ErrNoPending
	}
	armed, err := s.Timer.Active()
	if err != nil {
		return fmt.Errorf("check rollback timer: %w", err)
	}
	if !armed {
		s.pending.stop()
		s.pending = nil
		return ErrExpired
	}
	if err := s.Timer.Disarm(); err != nil {
		return fmt.Errorf("disarm rollback timer: %w", err)
	}
	s.pending.stop()
	s.pending = nil
	return nil
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
		slog.Error(fmt.Sprintf("firewall: rollback failed, host timer will restore: %v", err))
		s.pending = nil
		return
	}
	s.pending = nil
	if err := s.Timer.Disarm(); err != nil {
		slog.Warn(fmt.Sprintf("firewall: disarm after rollback: %v", err))
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
// rollback script with the host's nft after the timeout. Runner must reach the
// host for every call (use NsenterRunner from the control-plane container):
// the script file, the timer and nft all have to live on the host.
type SystemdTimer struct {
	Runner Runner
	Unit   string // e.g. "novusgate-fw-rollback"
	Path   string // host path for the rollback script
}

// Arm implements HostTimer.
func (t SystemdTimer) Arm(rollbackScript string, after time.Duration) error {
	if _, err := t.Runner.Run("", "nft", "--version"); err != nil {
		return fmt.Errorf("host cannot run nft, refusing to arm rollback: %w", err)
	}
	armed, err := t.Active()
	if err != nil {
		return err
	}
	if armed {
		return ErrRollbackArmed
	}
	// Clear a failed transient unit so systemd-run can reuse the name.
	t.resetFailed()
	if _, err := t.Runner.Run("", "mkdir", "-p", path.Dir(t.Path)); err != nil {
		return fmt.Errorf("create rollback directory: %w", err)
	}
	if _, err := t.Runner.Run(rollbackScript, "tee", t.Path); err != nil {
		return fmt.Errorf("write rollback script: %w", err)
	}
	secs := int(after / time.Second)
	if secs < 1 {
		secs = 1
	}
	if _, err := t.Runner.Run("", "systemd-run",
		"--unit="+t.Unit,
		fmt.Sprintf("--on-active=%ds", secs),
		"--timer-property=AccuracySec=1s",
		"nft", "-f", t.Path); err != nil {
		return fmt.Errorf("systemd-run: %w", err)
	}
	return nil
}

// Disarm implements HostTimer. A timer that is not loaded is already disarmed.
func (t SystemdTimer) Disarm() error {
	if _, err := t.Runner.Run("", "systemctl", "stop", t.Unit+".timer"); err != nil && !strings.Contains(err.Error(), "not loaded") {
		return fmt.Errorf("systemctl stop: %w", err)
	}
	t.resetFailed()
	return nil
}

// Active implements HostTimer: whether the rollback timer is still scheduled.
func (t SystemdTimer) Active() (bool, error) {
	out, err := t.Runner.Run("", "systemctl", "is-active", t.Unit+".timer")
	state := strings.TrimSpace(out)
	switch {
	case err == nil && state == "active":
		return true, nil
	case state == "inactive" || state == "failed" || state == "unknown":
		// is-active exits non-zero for these states.
		return false, nil
	case err != nil:
		return false, fmt.Errorf("systemctl is-active: %w", err)
	}
	return false, fmt.Errorf("unexpected timer state %q", state)
}

// resetFailed clears a failed transient unit; "not loaded" means there is
// nothing to clear.
func (t SystemdTimer) resetFailed() {
	if _, err := t.Runner.Run("", "systemctl", "reset-failed", t.Unit+".service"); err != nil && !strings.Contains(err.Error(), "not loaded") {
		slog.Error(fmt.Sprintf("firewall: reset-failed %s: %v", t.Unit, err))
	}
}
