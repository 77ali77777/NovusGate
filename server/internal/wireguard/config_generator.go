package wireguard

import (
	"fmt"
	"os"
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

// GenerateServerConfig generates the wg0.conf content for the server
func (g *ConfigGenerator) GenerateServerConfig(privateKey string, port int, addressCIDR string) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", addressCIDR))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", port))
	sb.WriteString("SaveConfig = false\n") // We manage peers manually/via DB
	sb.WriteString("PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE\n")
	sb.WriteString("PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE\n")

	return sb.String()
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
