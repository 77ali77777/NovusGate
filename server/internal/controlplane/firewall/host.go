package firewall

import (
	"fmt"
	"path"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

const (
	// PersistPath is the ruleset the boot unit loads before Docker starts.
	PersistPath = "/etc/novusgate/firewall.nft"
	// rollbackUnit and rollbackPath belong to the host-side rollback timer.
	rollbackUnit = "novusgate-fw-rollback"
	rollbackPath = "/var/lib/novusgate/fw-rollback.nft"
	// ConfirmTimeout is how long a confirmable change waits before rollback.
	ConfirmTimeout = 60 * time.Second
)

// NewHostEngine wires the engine to the real host. nft runs in the control
// plane's container (it shares the host's network namespace); the rollback
// timer, its script and the boot-time ruleset live on the host via nsenter.
func NewHostEngine(mode Mode, st Store) *Engine {
	host := nft.NsenterRunner{}
	applier := nft.NewSafeApplier(
		nft.Executor{Runner: nft.HostRunner{}},
		nft.SystemdTimer{Runner: host, Unit: rollbackUnit, Path: rollbackPath},
		ConfirmTimeout,
	)
	return &Engine{
		Mode:    mode,
		Store:   st,
		Applier: applier,
		Now:     time.Now,
		Detect: func() (HostInfo, error) {
			ports, egress, err := DetectHost(nft.HostRunner{})
			return HostInfo{SSHPorts: ports, Egress: egress}, err
		},
		Persist: func(script string) error { return WriteHostFile(host, PersistPath, script) },
		AfterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
	}
}

// WriteHostFile writes content to a host path through r (use nsenter).
func WriteHostFile(r nft.Runner, file, content string) error {
	if _, err := r.Run("", "mkdir", "-p", path.Dir(file)); err != nil {
		return fmt.Errorf("create %s: %w", path.Dir(file), err)
	}
	if _, err := r.Run(content, "tee", file); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	return nil
}
