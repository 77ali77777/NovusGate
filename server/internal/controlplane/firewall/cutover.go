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

// dockerUserRules are the matches and targets of the DOCKER-USER rules, in
// order. Traffic between VPN interfaces and Docker's bridges returns to
// Docker's own chains, so its isolation of containers stays; all other VPN
// traffic is accepted.
var dockerUserRules = [][]string{
	{"-i", "wg+", "-o", "docker0", "RETURN"},
	{"-i", "wg+", "-o", "br-+", "RETURN"},
	{"-i", "docker0", "-o", "wg+", "RETURN"},
	{"-i", "br-+", "-o", "wg+", "RETURN"},
	{"-i", "wg+", "ACCEPT"},
	{"-o", "wg+", "ACCEPT"},
}

// dockerUserArgs is a rule's spec as iptables -S prints it (without -A chain).
func dockerUserArgs(rule []string) []string {
	match, target := rule[:len(rule)-1], rule[len(rule)-1]
	return append(append(append([]string{}, match...), "-m", "comment", "--comment", dockerUserComment), "-j", target)
}

// ourDockerUserRules reads DOCKER-USER and returns the specs of the rules
// marked as ours, in order. ok is false when the chain does not exist
// (Docker not managing iptables); any other failure is an error.
func ourDockerUserRules(r nft.Runner) (rules [][]string, ok bool, err error) {
	out, err := r.Run("", "iptables", "-S", "DOCKER-USER")
	if err != nil {
		if msg := err.Error() + out; strings.Contains(msg, "No chain") || strings.Contains(msg, "does not exist") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read DOCKER-USER: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A DOCKER-USER ") && strings.Contains(line, dockerUserComment) {
			rules = append(rules, splitIptablesArgs(strings.TrimPrefix(line, "-A DOCKER-USER ")))
		}
	}
	return rules, true, nil
}

// allowVPNThroughDocker lets VPN traffic pass Docker's filter FORWARD chain,
// whose policy is DROP. In nftables a packet must be accepted by every base
// chain on the hook, so without this, traffic table inet novusgate allows
// (full tunnel to the internet, the admin VPN wg0, which has no wg-quick
// PostUp ACCEPT) is still dropped there. DOCKER-USER is the chain Docker
// leaves to the administrator. The forward chain of table inet novusgate runs
// first (priority filter - 10) and drops everything the VPN rules do not
// allow, so the ACCEPTs only pass what it already let through. Rules already
// in place and in order are left alone; otherwise ours are replaced.
func allowVPNThroughDocker(r nft.Runner) error {
	have, ok, err := ourDockerUserRules(r)
	if err != nil {
		return err
	}
	if !ok {
		slog.Info("firewall: no DOCKER-USER chain; Docker's FORWARD chain is left as it is")
		return nil
	}
	want := make([]string, len(dockerUserRules))
	for i, rule := range dockerUserRules {
		want[i] = strings.Join(dockerUserArgs(rule), " ")
	}
	got := make([]string, len(have))
	for i, args := range have {
		got[i] = strings.Join(args, " ")
	}
	if strings.Join(got, "\n") == strings.Join(want, "\n") {
		return nil
	}
	for _, args := range have {
		if _, err := r.Run("", "iptables", append([]string{"-D", "DOCKER-USER"}, args...)...); err != nil {
			return fmt.Errorf("remove an old DOCKER-USER rule: %w", err)
		}
	}
	for i, rule := range dockerUserRules {
		args := append([]string{"-I", "DOCKER-USER", strconv.Itoa(i + 1)}, dockerUserArgs(rule)...)
		if _, err := r.Run("", "iptables", args...); err != nil {
			return fmt.Errorf("let VPN traffic through DOCKER-USER: %w", err)
		}
	}
	return nil
}

// RemoveVPNThroughDocker removes the DOCKER-USER rules of the nftables
// hand-over; it runs outside nftables mode. There VPN traffic is filtered in
// iptables' NOVUSGATE-VPN, and Docker puts its DOCKER-USER jump first in
// FORWARD, so an ACCEPT left in DOCKER-USER would skip every VPN rule. The
// result is saved for boot when something was removed. It returns the
// number of removed rules.
func RemoveVPNThroughDocker(r nft.Runner) (int, error) {
	have, ok, err := ourDockerUserRules(r)
	if err != nil || !ok {
		return 0, err
	}
	for i, args := range have {
		if _, err := r.Run("", "iptables", append([]string{"-D", "DOCKER-USER"}, args...)...); err != nil {
			return i, fmt.Errorf("remove a DOCKER-USER rule: %w", err)
		}
	}
	if len(have) > 0 {
		if _, err := r.Run("", "netfilter-persistent", "save"); err != nil {
			slog.Error(fmt.Sprintf("firewall: netfilter-persistent save failed (the next start removes them again): %v", err))
		}
	}
	return len(have), nil
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
