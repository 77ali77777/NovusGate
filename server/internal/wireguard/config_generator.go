package wireguard

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// GetServerEndpoint returns the server endpoint from environment or default
func GetServerEndpoint() string {
	if ep := os.Getenv("WG_SERVER_ENDPOINT"); ep != "" {
		return ep
	}
	// Fallback to localhost for development
	return "127.0.0.1"
}

const (
	// DefaultServerPort is the default WireGuard port
	DefaultServerPort = 51820
)

// ConfigGenerator handles WireGuard configuration generation
type ConfigGenerator struct{}

// NewConfigGenerator creates a new ConfigGenerator
func NewConfigGenerator() *ConfigGenerator {
	return &ConfigGenerator{}
}

// GenerateServerConfig generates a hub interface's wg-quick config. egress
// is the host's internet interface (EgressInterface), written as a plain
// name: the host's wg-quick AppArmor profile (Ubuntu 26.04) does not let
// PostUp run awk, so "-o $(ip route get … | awk …)" came out empty and
// wg-quick removed the interface. Without a valid name the masquerade is
// left out (nftables mode masquerades in table inet novusgate).
func (g *ConfigGenerator) GenerateServerConfig(privateKey string, port int, addressCIDR string, egress string) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", addressCIDR))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", port))
	sb.WriteString("SaveConfig = false\n") // We manage peers manually/via DB
	sb.WriteString(postUpDown(egress))

	return sb.String()
}

// ifaceNameRe is a Linux interface name (at most 15 bytes): nothing a shell
// would interpret, since PostUp is run by a shell.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,14}$`)

// postUpDown returns the PostUp and PostDown lines: forwarding through the
// interface, and masquerading out of egress when it is a valid name.
func postUpDown(egress string) string {
	up := "iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT"
	down := "iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT"
	if ifaceNameRe.MatchString(egress) {
		up += "; iptables -t nat -A POSTROUTING -o " + egress + " -j MASQUERADE"
		down += "; iptables -t nat -D POSTROUTING -o " + egress + " -j MASQUERADE"
	}
	return "PostUp = " + up + "\nPostDown = " + down + "\n"
}

// EgressInterface returns the host's internet interface (the route to
// 8.8.8.8), or "" when there is none or it is not a plain name.
func EgressInterface() string {
	out, err := run("ip", "-o", "route", "get", "8.8.8.8")
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" && ifaceNameRe.MatchString(fields[i+1]) {
			return fields[i+1]
		}
	}
	return ""
}

// legacyPostUpMarker is in the PostUp of configs older versions wrote.
const legacyPostUpMarker = "$(ip route get"

// rewriteLegacyPostUp replaces an older version's PostUp/PostDown (which
// needs awk) with plain lines; it reports whether anything changed.
func rewriteLegacyPostUp(config, egress string) (string, bool) {
	if !strings.Contains(config, legacyPostUpMarker) {
		return config, false
	}
	var out strings.Builder
	written := false
	for _, line := range strings.SplitAfter(config, "\n") {
		key, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch strings.TrimSpace(key) {
		case "PostUp", "PostDown":
			if !written {
				out.WriteString(postUpDown(egress))
				written = true
			}
		default:
			out.WriteString(line)
		}
	}
	return out.String(), true
}

// GeneratePeerConfig generates the client/peer configuration file content
func (g *ConfigGenerator) GeneratePeerConfig(clientPrivateKey, serverPublicKey, serverEndpoint, clientIP string, allowedIPs string) string {
	return g.GeneratePeerConfigDNS(clientPrivateKey, serverPublicKey, serverEndpoint, clientIP, allowedIPs, "")
}

// GeneratePeerConfigDNS is GeneratePeerConfig with a DNS server for the
// tunnel (full tunnel); an empty dns writes no DNS line.
func (g *ConfigGenerator) GeneratePeerConfigDNS(clientPrivateKey, serverPublicKey, serverEndpoint, clientIP, allowedIPs, dns string) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", clientIP))
	if dns != "" {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", dns))
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPublicKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", serverEndpoint))
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowedIPs))
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}

// GeneratePeerEntryForServer returns the [Peer] block to be added to server's interface (runtime)
func (g *ConfigGenerator) GeneratePeerEntryForServer(clientPublicKey, clientIP string) string {
	return fmt.Sprintf("peer: %s, allowedips: %s", clientPublicKey, clientIP)
}
