// Package nft compiles NovusGate's firewall model into an nftables script for
// its own table (inet novusgate) and applies it safely.
package nft

import (
	"fmt"
	"net/netip"
	"time"
)

// Protocol is a layer-4 protocol used by the firewall model.
type Protocol string

const (
	TCP  Protocol = "tcp"
	UDP  Protocol = "udp"
	ICMP Protocol = "icmp"
	All  Protocol = "all"
)

// PortRange is an inclusive port range; a single port has From == To.
type PortRange struct {
	From uint16
	To   uint16
}

// String renders the range in nft syntax ("443" or "8000-8100").
func (r PortRange) String() string {
	if r.From == r.To {
		return fmt.Sprintf("%d", r.From)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// Service opens a host port in the input chain.
type Service struct {
	ID        string
	Proto     Protocol // tcp or udp
	Ports     PortRange
	Sources   []netip.Prefix // empty means any source
	Interface string         // empty means any interface
}

// BlockedEntry drops all traffic from a prefix until Expires (nil = permanent).
type BlockedEntry struct {
	Prefix  netip.Prefix
	Expires *time.Time
}

// PortForward publishes TargetIP:TargetPort (a VPN node) on PublicPort of the
// egress interface.
type PortForward struct {
	ID         string
	Proto      Protocol // tcp or udp
	PublicPort uint16
	TargetIP   netip.Addr
	TargetPort uint16
}

// VPNNetwork is one WireGuard interface with its subnet and UDP listen port.
type VPNNetwork struct {
	Interface  string
	CIDR       netip.Prefix
	ListenPort uint16
}

// VPNRule controls forwarding between VPN subnets; rules are evaluated in order.
type VPNRule struct {
	ID     string
	Src    netip.Prefix
	Dst    netip.Prefix
	Proto  Protocol
	Ports  []PortRange // only for tcp and udp
	Action string      // accept, drop or reject
}

// Ruleset is the complete desired state of table inet novusgate.
type Ruleset struct {
	SSHPorts        []uint16
	EgressInterface string
	Networks        []VPNNetwork
	Services        []Service
	Blocked         []BlockedEntry
	Forwards        []PortForward
	VPNRules        []VPNRule
	Egress          []netip.Addr // full-tunnel nodes allowed to reach the internet
}

const (
	// TableName is the only nftables table NovusGate owns.
	TableName = "novusgate"
	// AdminInterface carries the admin network (panel and database access).
	AdminInterface = "wg0"
	// VPNInterfacePattern matches every NovusGate WireGuard interface.
	VPNInterfacePattern = "wg*"
)

var (
	// LegacyWireGuardRange is the UDP range the installer has always opened.
	LegacyWireGuardRange = PortRange{From: 51820, To: 51900}
	// AdminPorts are reachable only from the admin interface (panel, database).
	AdminPorts = []uint16{3007, 5432}
	// APIPorts are reachable from every VPN interface (control-plane API, gRPC).
	APIPorts = []uint16{8080, 8443}
)
