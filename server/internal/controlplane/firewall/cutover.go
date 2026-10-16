package firewall

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// BootUnit loads PersistPath on the host before Docker starts; it is
// installed by setup-firewall.sh.
const BootUnit = "novusgate-firewall.service"

// minHostNft is the oldest nft whose parser accepts the compiled ruleset and
// the rollback snapshot (verified by scripts/nft-versions-check.sh).
var minHostNft = [3]int{1, 0, 2}

var nftVersionRe = regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`)

// CheckHost refuses nft mode on a host that could not keep the firewall
// across a reboot or a rollback: host nft older than 1.0.2 (Ubuntu 20.04),
// a missing boot unit, or iptables on the legacy backend (whose rules the
// container's iptables cannot see). r must run on the host (nsenter).
func CheckHost(r nft.Runner) error {
	out, err := r.Run("", "nft", "--version")
	if err != nil {
		return fmt.Errorf("nftables is not installed on the host (run Center → Update, which runs setup-firewall.sh): %w", err)
	}
	m := nftVersionRe.FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("cannot read the host nftables version from %q", strings.TrimSpace(out))
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	if versionLess(v, minHostNft) {
		return fmt.Errorf("host nftables %s is older than 1.0.2 (Ubuntu 20.04?): FIREWALL_ENGINE=nft is not supported on this host", strings.TrimSpace(out))
	}
	if out, err := r.Run("", "systemctl", "is-enabled", BootUnit); err != nil || strings.TrimSpace(out) != "enabled" {
		return fmt.Errorf("%s is not enabled on the host (run Center → Update, which runs setup-firewall.sh); without it the host would boot without its firewall", BootUnit)
	}
	out, err = r.Run("", "iptables", "-V")
	if err != nil {
		return fmt.Errorf("cannot read the host iptables backend: %w", err)
	}
	if !strings.Contains(out, "nf_tables") {
		return fmt.Errorf("host iptables %q is not on the nf_tables backend; FIREWALL_ENGINE=nft is not supported on this host", strings.TrimSpace(out))
	}
	return nil
}

func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// CutoverIptables hands INPUT filtering from iptables to table inet
// novusgate, which must already be applied. The policy becomes ACCEPT first
// (nftables already drops by default), so removing the rules never drops an
// established connection. Then every plain ACCEPT/DROP rule in INPUT is
// deleted by its own spec, so a jump fail2ban inserts or removes meanwhile
// can never shift what is deleted. REJECT bans and jumps to other tools'
// chains (fail2ban, CrowdSec, ...) stay. The result is saved for boot. It is
// idempotent, and every control-plane start repeats it. It returns the
// number of deleted rules.
func CutoverIptables(r nft.Runner) (int, error) {
	if _, err := r.Run("", "iptables", "-P", "INPUT", "ACCEPT"); err != nil {
		return 0, fmt.Errorf("set iptables INPUT policy to ACCEPT: %w", err)
	}
	out, err := r.Run("", "iptables", "-S", "INPUT")
	if err != nil {
		return 0, fmt.Errorf("read iptables INPUT: %w", err)
	}
	deleted := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		args := splitIptablesArgs(strings.TrimPrefix(line, "-A INPUT "))
		if target := ruleTarget(args); target != "ACCEPT" && target != "DROP" {
			slog.Info(fmt.Sprintf("firewall: hand-over keeps iptables rule: %s", line))
			continue
		}
		if _, err := r.Run("", "iptables", append([]string{"-D", "INPUT"}, args...)...); err != nil {
			return deleted, fmt.Errorf("delete iptables rule %q: %w", line, err)
		}
		deleted++
	}
	if err := allowVPNThroughDocker(r); err != nil {
		return deleted, err
	}
	if _, err := r.Run("", "netfilter-persistent", "save"); err != nil {
		slog.Error(fmt.Sprintf("firewall: netfilter-persistent save failed (the next start repeats the hand-over): %v", err))
	}
	return deleted, nil
}

// dockerUserComment marks the DOCKER-USER rules the hand-over adds.
const dockerUserComment = "novusgate-docker-user"

// allowVPNThroughDocker lets VPN interfaces pass Docker's filter FORWARD
// chain, whose policy is DROP. In nftables a packet must be accepted by every
// base chain on the hook, so without this, traffic table inet novusgate
// allows (full tunnel to the internet, the admin VPN wg0, which has no
// wg-quick PostUp ACCEPT) is still dropped there. DOCKER-USER is the chain
// Docker leaves to the administrator. The forward chain of table inet
// novusgate runs first (priority filter - 10) and drops everything the VPN
// rules do not allow, so these ACCEPTs only pass what it already let through.
// Without DOCKER-USER (Docker not managing iptables) nothing is added.
func allowVPNThroughDocker(r nft.Runner) error {
	if _, err := r.Run("", "iptables", "-S", "DOCKER-USER"); err != nil {
		slog.Info("firewall: no DOCKER-USER chain; Docker's FORWARD chain is left as it is")
		return nil
	}
	for _, dir := range []string{"-i", "-o"} {
		spec := []string{"DOCKER-USER", dir, "wg+", "-m", "comment", "--comment", dockerUserComment, "-j", "ACCEPT"}
		if _, err := r.Run("", "iptables", append([]string{"-C"}, spec...)...); err == nil {
			continue
		}
		if _, err := r.Run("", "iptables", append([]string{"-I"}, spec...)...); err != nil {
			return fmt.Errorf("let VPN traffic through DOCKER-USER (%s): %w", dir, err)
		}
	}
	return nil
}

// ruleTarget returns the -j target of a rule spec.
func ruleTarget(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-j" {
			return args[i+1]
		}
	}
	return ""
}

// splitIptablesArgs splits one `iptables -S` rule into arguments, honouring
// the double quotes (and \" escapes) iptables prints around comments.
func splitIptablesArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == '"':
			inQuote, have = !inQuote, true
		case c == ' ' && !inQuote:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}
