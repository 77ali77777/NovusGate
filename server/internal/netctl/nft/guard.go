package nft

import (
	"fmt"
	"net/netip"
	"time"
)

// Protection lists what a ruleset must never cut off: every port sshd
// listens on and the addresses the operator is connected from right now.
type Protection struct {
	SSHPorts []uint16
	Addrs    []netip.Addr
}

// CheckProtection refuses a ruleset that would lock the operator out. It
// fails closed: with no detected SSH port it refuses rather than guessing.
func CheckProtection(rs Ruleset, p Protection, now time.Time) error {
	if len(p.SSHPorts) == 0 {
		return fmt.Errorf("no SSH port detected; refusing to apply firewall changes")
	}
	for _, port := range p.SSHPorts {
		if !contains(rs.SSHPorts, port) {
			return fmt.Errorf("ruleset does not keep SSH port %d open", port)
		}
	}
	for _, addr := range p.Addrs {
		addr = addr.Unmap()
		for _, r := range rs.IPRules {
			if r.Action == "block" && r.Prefix.Contains(addr) {
				return fmt.Errorf("IP rule %s would block the current session from %s", r.ID, addr)
			}
		}
		for _, b := range rs.Blocked {
			if b.Expires != nil && !b.Expires.After(now) {
				continue
			}
			if b.Prefix.Contains(addr) {
				return fmt.Errorf("blocked entry %s would cut off the current session from %s", b.Prefix, addr)
			}
		}
	}
	return nil
}
