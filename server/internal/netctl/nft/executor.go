package nft

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs a command on the host, feeding stdin. It returns stdout only;
// on failure the error carries stderr.
type Runner interface {
	Run(stdin string, name string, args ...string) (string, error)
}

// HostRunner runs commands directly (the control plane shares the host's
// network namespace) and falls back to nsenter into PID 1's namespaces when
// the binary is missing in the container.
type HostRunner struct{}

// Run implements Runner.
func (HostRunner) Run(stdin string, name string, args ...string) (string, error) {
	out, err := run(stdin, name, args...)
	if err == nil {
		return out, nil
	}
	if _, lookErr := exec.LookPath(name); lookErr == nil {
		return out, err
	}
	return NsenterRunner{}.Run(stdin, name, args...)
}

// NsenterRunner always runs commands in the host's mount, UTS, IPC and
// network namespaces, so files and systemd units it touches are the host's.
type NsenterRunner struct{}

// Run implements Runner.
func (NsenterRunner) Run(stdin string, name string, args ...string) (string, error) {
	nsArgs := append([]string{"-t", "1", "-m", "-u", "-i", "-n", "--", name}, args...)
	return run(stdin, "nsenter", nsArgs...)
}

func run(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// removeTable is the script that leaves the host without our table; it is
// the snapshot when the table does not exist yet.
const removeTable = "table inet " + TableName + "\ndelete table inet " + TableName + "\n"

// Executor validates, applies and snapshots table inet novusgate.
type Executor struct {
	Runner Runner
}

// Check validates a script against the kernel without changing anything.
func (e Executor) Check(script string) error {
	if _, err := e.Runner.Run(script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft check failed: %w", err)
	}
	return nil
}

// Apply loads a script atomically.
func (e Executor) Apply(script string) error {
	if _, err := e.Runner.Run(script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft apply failed: %w", err)
	}
	return nil
}

// Snapshot returns a script that restores the current table exactly,
// including dynamic set elements such as timed bans.
func (e Executor) Snapshot() (string, error) {
	out, err := e.Runner.Run("", "nft", "list", "table", "inet", TableName)
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return removeTable, nil
		}
		return "", fmt.Errorf("nft list failed: %w", err)
	}
	return removeTable + out, nil
}
