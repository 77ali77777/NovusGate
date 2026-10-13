package nft

import (
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs a command on the host, feeding stdin, and returns its combined output.
type Runner interface {
	Run(stdin string, name string, args ...string) (string, error)
}

// HostRunner runs commands directly (the control plane shares the host's
// network namespace) and falls back to nsenter into PID 1's namespaces.
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
	nsArgs := append([]string{"-t", "1", "-m", "-u", "-i", "-n", "--", name}, args...)
	return run(stdin, "nsenter", nsArgs...)
}

func run(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
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
	if out, err := e.Runner.Run(script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft check failed: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Apply loads a script atomically.
func (e Executor) Apply(script string) error {
	if out, err := e.Runner.Run(script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft apply failed: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Snapshot returns a script that restores the current table exactly,
// including dynamic set elements such as timed bans.
func (e Executor) Snapshot() (string, error) {
	out, err := e.Runner.Run("", "nft", "list", "table", "inet", TableName)
	if err != nil {
		if strings.Contains(out, "No such file or directory") {
			return removeTable, nil
		}
		return "", fmt.Errorf("nft list failed: %v: %s", err, strings.TrimSpace(out))
	}
	return removeTable + out, nil
}
