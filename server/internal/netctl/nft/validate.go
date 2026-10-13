package nft

import (
	"fmt"
	"regexp"
)

var (
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// reservedPorts can never be opened as public services or used for forwards.
func reservedPorts() map[uint16]bool {
	m := map[uint16]bool{}
	for _, p := range append(append([]uint16{}, AdminPorts...), APIPorts...) {
		m[p] = true
	}
	return m
}

// Validate rejects any ruleset that cannot be compiled safely. Identifiers and
// interface names are restricted so nothing user-supplied can break out of the
// generated nft syntax.
func Validate(rs Ruleset) error {
	if len(rs.SSHPorts) == 0 {
		return fmt.Errorf("at least one SSH port is required")
	}
	for _, p := range rs.SSHPorts {
		if p == 0 {
			return fmt.Errorf("invalid SSH port 0")
		}
	}
	if !ifaceRe.MatchString(rs.EgressInterface) {
		return fmt.Errorf("invalid egress interface %q", rs.EgressInterface)
	}
	for _, n := range rs.Networks {
		if !ifaceRe.MatchString(n.Interface) {
			return fmt.Errorf("invalid network interface %q", n.Interface)
		}
		if !n.CIDR.IsValid() || !n.CIDR.Addr().Is4() {
			return fmt.Errorf("network %s: CIDR must be IPv4", n.Interface)
		}
	}
	reserved := reservedPorts()
	for _, s := range rs.Services {
		if !idRe.MatchString(s.ID) {
			return fmt.Errorf("invalid service id %q", s.ID)
		}
		if s.Proto != TCP && s.Proto != UDP {
			return fmt.Errorf("service %s: protocol must be tcp or udp", s.ID)
		}
		if s.Ports.From == 0 || s.Ports.To < s.Ports.From {
			return fmt.Errorf("service %s: invalid port range %s", s.ID, s.Ports)
		}
		if s.Interface != "" && !ifaceRe.MatchString(s.Interface) {
			return fmt.Errorf("service %s: invalid interface %q", s.ID, s.Interface)
		}
		for _, src := range s.Sources {
			if !src.IsValid() {
				return fmt.Errorf("service %s: invalid source", s.ID)
			}
		}
		if s.Proto == TCP && !containsString(vpnInterfaces(rs), s.Interface) {
			for p := range reserved {
				if p >= s.Ports.From && p <= s.Ports.To {
					return fmt.Errorf("service %s: port %d is reserved for VPN-only admin services", s.ID, p)
				}
			}
		}
	}
	for _, b := range rs.Blocked {
		if !b.Prefix.IsValid() {
			return fmt.Errorf("invalid blocked prefix")
		}
	}
	for _, f := range rs.Forwards {
		if !idRe.MatchString(f.ID) {
			return fmt.Errorf("invalid forward id %q", f.ID)
		}
		if f.Proto != TCP && f.Proto != UDP {
			return fmt.Errorf("forward %s: protocol must be tcp or udp", f.ID)
		}
		if f.PublicPort == 0 || f.TargetPort == 0 {
			return fmt.Errorf("forward %s: ports must be 1-65535", f.ID)
		}
		if f.Proto == TCP && (reserved[f.PublicPort] || contains(rs.SSHPorts, f.PublicPort)) {
			return fmt.Errorf("forward %s: public port %d is reserved", f.ID, f.PublicPort)
		}
		if f.Proto == UDP {
			for _, wg := range wireGuardRanges(rs) {
				if f.PublicPort >= wg.From && f.PublicPort <= wg.To {
					return fmt.Errorf("forward %s: public port %d is a WireGuard port", f.ID, f.PublicPort)
				}
			}
		}
		if _, ok := networkFor(rs.Networks, f.TargetIP); !ok {
			return fmt.Errorf("forward %s: target %s is not inside any VPN network", f.ID, f.TargetIP)
		}
	}
	for _, r := range rs.VPNRules {
		if !idRe.MatchString(r.ID) {
			return fmt.Errorf("invalid VPN rule id %q", r.ID)
		}
		if !r.Src.IsValid() || !r.Dst.IsValid() || !r.Src.Addr().Is4() || !r.Dst.Addr().Is4() {
			return fmt.Errorf("VPN rule %s: source and destination must be IPv4 prefixes", r.ID)
		}
		switch r.Proto {
		case TCP, UDP:
		case ICMP, All:
			if len(r.Ports) > 0 {
				return fmt.Errorf("VPN rule %s: ports are only allowed for tcp and udp", r.ID)
			}
		default:
			return fmt.Errorf("VPN rule %s: unknown protocol %q", r.ID, r.Proto)
		}
		for _, p := range r.Ports {
			if p.From == 0 || p.To < p.From {
				return fmt.Errorf("VPN rule %s: invalid port range %s", r.ID, p)
			}
		}
		if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
			return fmt.Errorf("VPN rule %s: unknown action %q", r.ID, r.Action)
		}
	}
	for _, r := range rs.IPRules {
		if !idRe.MatchString(r.ID) {
			return fmt.Errorf("invalid IP rule id %q", r.ID)
		}
		if !r.Prefix.IsValid() {
			return fmt.Errorf("IP rule %s: invalid prefix", r.ID)
		}
		if r.Action != "block" && r.Action != "allow" {
			return fmt.Errorf("IP rule %s: action must be block or allow", r.ID)
		}
		if r.Proto != "" && r.Proto != TCP && r.Proto != UDP {
			return fmt.Errorf("IP rule %s: protocol must be tcp, udp or empty", r.ID)
		}
		if len(r.Ports) > 0 && r.Proto == "" {
			return fmt.Errorf("IP rule %s: ports need tcp or udp", r.ID)
		}
		if r.Action == "block" && len(r.Ports) == 0 {
			return fmt.Errorf("IP rule %s: whole-address blocks belong in the blocked set", r.ID)
		}
		for _, p := range r.Ports {
			if p.From == 0 || p.To < p.From {
				return fmt.Errorf("IP rule %s: invalid port range %s", r.ID, p)
			}
		}
	}
	for _, a := range rs.Egress {
		if !a.Is4() {
			return fmt.Errorf("egress address %s must be IPv4", a)
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func contains(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// ValidInterfaceName reports whether name is a Linux interface name that can
// be rendered safely into the ruleset.
func ValidInterfaceName(name string) bool {
	return ifaceRe.MatchString(name)
}
