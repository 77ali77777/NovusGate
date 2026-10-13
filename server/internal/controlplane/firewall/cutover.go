package firewall

import (
	"fmt"
	"log"
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
// established connection. Then every INPUT rule except fail2ban's jumps is
// deleted, and the result is saved for boot. It is idempotent, and every
// control-plane start repeats it. It returns the number of deleted rules.
func CutoverIptables(r nft.Runner) (int, error) {
	if _, err := r.Run("", "iptables", "-P", "INPUT", "ACCEPT"); err != nil {
		return 0, fmt.Errorf("set iptables INPUT policy to ACCEPT: %w", err)
	}
	out, err := r.Run("", "iptables", "-S", "INPUT")
	if err != nil {
		return 0, fmt.Errorf("read iptables INPUT: %w", err)
	}
	var nums []int
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		n++
		if strings.Contains(line, " -j f2b-") {
			continue
		}
		nums = append(nums, n)
	}
	// Delete from the bottom, so the remaining rule numbers stay valid.
	for i := len(nums) - 1; i >= 0; i-- {
		if _, err := r.Run("", "iptables", "-D", "INPUT", strconv.Itoa(nums[i])); err != nil {
			return len(nums) - 1 - i, fmt.Errorf("delete iptables INPUT rule %d: %w", nums[i], err)
		}
	}
	if _, err := r.Run("", "netfilter-persistent", "save"); err != nil {
		log.Printf("firewall: netfilter-persistent save failed (the next start repeats the hand-over): %v", err)
	}
	return len(nums), nil
}
