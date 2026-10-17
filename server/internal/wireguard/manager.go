package wireguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Manager controls the WireGuard interface
type Manager struct {
	InterfaceName string
	ConfigPath    string
}

// NewManager creates a new WireGuard manager
func NewManager(interfaceName string) *Manager {
	return &Manager{
		InterfaceName: interfaceName,
		ConfigPath:    fmt.Sprintf("/etc/wireguard/%s.conf", interfaceName),
	}
}

// Init verifies that the host has wireguard-tools: every wg, wg-quick and
// ip command runs on the host (see command).
func (m *Manager) Init() error {
	if out, err := run("wg", "--version"); err != nil {
		return fmt.Errorf("wireguard-tools not found on the host (wg --version: %s): %w", out, err)
	}
	return nil
}

// SetupInterface writes the config (/etc/wireguard is the host's, mounted)
// and brings the interface up, or restarts it so a new config applies.
func (m *Manager) SetupInterface(configContent string) error {
	if err := os.WriteFile(m.ConfigPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	if m.isInterfaceUp() {
		return m.Restart()
	}
	return m.Up()
}

// unit is the host's systemd unit of the interface, like wg-quick@wg0.
func (m *Manager) unit() string { return "wg-quick@" + m.InterfaceName }

// Up makes sure the interface runs as its systemd unit on the host and comes
// back at boot. A running unit is left alone. An interface brought up
// outside systemd (by hand, or from the container by an older version) is
// handed over to the unit: the unit would fail on it ("already exists").
// Runtime peers are not in the config (SaveConfig = false): callers restore
// them after Up and Restart.
func (m *Manager) Up() error {
	if out, err := run("systemctl", "enable", m.unit()); err != nil {
		return fmt.Errorf("systemctl enable %s failed: %s: %w", m.unit(), out, err)
	}
	if m.isInterfaceUp() {
		if m.unitActive() {
			return nil
		}
		m.downOutsideSystemd()
	}
	return m.systemctl("start")
}

// Restart applies a new config, or brings back an interface that is
// misbehaving, through its systemd unit.
func (m *Manager) Restart() error {
	if out, err := run("systemctl", "enable", m.unit()); err != nil {
		return fmt.Errorf("systemctl enable %s failed: %s: %w", m.unit(), out, err)
	}
	if m.isInterfaceUp() && !m.unitActive() {
		m.downOutsideSystemd()
		return m.systemctl("start")
	}
	return m.systemctl("restart")
}

// Down stops the interface for good (its network is deleted): the unit is
// disabled and stopped; an interface left behind is removed.
func (m *Manager) Down() error {
	// A unit that never existed (an interface brought up by hand) is fine.
	if out, err := run("systemctl", "disable", "--now", m.unit()); err != nil {
		slog.Info(fmt.Sprintf("[WG] systemctl disable --now %s: %s: %v", m.unit(), out, err))
	}
	if m.isInterfaceUp() {
		if out, err := run("ip", "link", "delete", m.InterfaceName); err != nil {
			return fmt.Errorf("ip link delete %s failed: %s: %w", m.InterfaceName, out, err)
		}
	}
	return nil
}

func (m *Manager) unitActive() bool {
	_, err := run("systemctl", "is-active", "--quiet", m.unit())
	return err == nil
}

// downOutsideSystemd takes down an interface its unit does not own; a
// failure shows up when the unit then starts.
func (m *Manager) downOutsideSystemd() {
	if out, err := run("wg-quick", "down", m.InterfaceName); err != nil {
		slog.Warn(fmt.Sprintf("[WG] wg-quick down %s: %s: %v", m.InterfaceName, out, err))
	}
}

// systemctl runs an action on the unit; a failure carries the unit's last
// journal lines, which say why (systemctl itself only says "failed").
func (m *Manager) systemctl(action string) error {
	out, err := run("systemctl", action, m.unit())
	if err == nil {
		return nil
	}
	journal, jerr := run("journalctl", "-u", m.unit(), "-n", "5", "--no-pager", "-o", "cat")
	if jerr != nil {
		journal = "(journal not readable: " + jerr.Error() + ")"
	}
	return fmt.Errorf("systemctl %s %s failed: %s %s: %w", action, m.unit(), out, journal, err)
}

// CreateServerConfig generates and writes the server configuration (generates new key)
func (m *Manager) CreateServerConfig(addressCIDR string, port int, peers []string) error {
	// 1. Generate Private Key
	privKey, err := m.generatePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// 2. Generate Config Content
	gen := NewConfigGenerator()
	configContent := gen.GenerateServerConfig(privKey, port, addressCIDR)

	// 3. Write and Setup
	return m.SetupInterface(configContent)
}

// CreateServerConfigWithKey uses an existing private key to create the server config
func (m *Manager) CreateServerConfigWithKey(privateKey string, addressCIDR string, port int) error {
	// Generate Config Content using provided key
	gen := NewConfigGenerator()
	configContent := gen.GenerateServerConfig(privateKey, port, addressCIDR)

	// Write and Setup
	return m.SetupInterface(configContent)
}

func (m *Manager) generatePrivateKey() (string, error) {
	priv, _, err := GenerateKeys()
	return priv, err
}

// AddPeer adds a peer to the running interface
func (m *Manager) AddPeer(publicKey, allowedIPs string) error {
	// wg set wg0 peer <key> allowed-ips <ips>
	cmd, cancel := command("wg", "set", m.InterfaceName, "peer", publicKey, "allowed-ips", allowedIPs)
	defer cancel()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add peer: %s: %w", string(output), err)
	}
	return nil
}

// UpdatePeerAllowedIPs updates the allowed-ips for an existing peer
func (m *Manager) UpdatePeerAllowedIPs(publicKey, allowedIPs string) error {
	// wg set wg0 peer <key> allowed-ips <ips>
	// This command updates the peer if it exists
	cmd, cancel := command("wg", "set", m.InterfaceName, "peer", publicKey, "allowed-ips", allowedIPs)
	defer cancel()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update peer allowed-ips: %s: %w", string(output), err)
	}
	return nil
}

// RemovePeer removes a peer from the running interface
func (m *Manager) RemovePeer(publicKey string) error {
	// wg set wg0 peer <key> remove
	cmd, cancel := command("wg", "set", m.InterfaceName, "peer", publicKey, "remove")
	defer cancel()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove peer: %s: %w", string(output), err)
	}
	return nil
}

// IsUp reports whether the interface exists on the host.
func (m *Manager) IsUp() bool { return m.isInterfaceUp() }

func (m *Manager) isInterfaceUp() bool { return interfaceExists(m.InterfaceName) }

// interfaceExists looks the interface up directly: the control plane shares
// the host's network namespace (replaced in tests).
var interfaceExists = func(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// GetPublicKey retrieves the server's public key by deriving it from the private key in the config
// If config doesn't exist, it generates and saves new keys
func (m *Manager) GetPublicKey() (string, error) {
	// 1. Try to read config to find PrivateKey
	content, err := os.ReadFile(m.ConfigPath)
	if err != nil {
		// Config doesn't exist - generate keys and create minimal config
		slog.Info("[INFO] Config file not found, generating new server keys...")
		privateKey, err := m.generatePrivateKey()
		if err != nil {
			return "", fmt.Errorf("failed to generate private key: %w", err)
		}
		
		// Create a minimal config with the generated key
		// Use 51820 as fallback port if not specified, but this path is usually for recovery
		configContent := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.99.0.1/24\nListenPort = 51820\n", privateKey)
		
		// Ensure directory exists
		configDir := "/etc/wireguard"
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return "", fmt.Errorf("failed to create config directory: %w", err)
		}
		
		if err := os.WriteFile(m.ConfigPath, []byte(configContent), 0600); err != nil {
			return "", fmt.Errorf("failed to write config: %w", err)
		}
		
		return PublicKey(privateKey)
	}
	
	// 2. Parse existing config for PrivateKey
	privateKey := parsePrivateKey(string(content))

	if privateKey == "" {
		return "", fmt.Errorf("private key not found in config")
	}

	// 3. Derive Public Key
	return PublicKey(privateKey)
}

// PeerStatus contains real-time information about a WireGuard peer
type PeerStatus struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          string 
	LatestHandshakeTime int64
	TransferRx          int64
	TransferTx          int64
}

// GetPeers returns the status of all peers on the interface
func (m *Manager) GetPeers() (map[string]PeerStatus, error) {
	cmd, cancel := command("wg", "show", m.InterfaceName, "dump")
	defer cancel()
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to dump wg status: %w", err)
	}

	peers := make(map[string]PeerStatus)
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		fields := strings.Fields(line)
		// Skip interface config line (usually the first one) or peers with too few fields
		if len(fields) < 8 {
			continue
		}

		status := PeerStatus{
			PublicKey:  fields[0],
			Endpoint:   fields[2],
			AllowedIPs: fields[3],
		}
		
		fmt.Sscanf(fields[4], "%d", &status.LatestHandshakeTime)
		fmt.Sscanf(fields[5], "%d", &status.TransferRx)
		fmt.Sscanf(fields[6], "%d", &status.TransferTx)

		peers[status.PublicKey] = status
	}

	return peers, nil
}



// parsePrivateKey returns the PrivateKey value of a wg-quick config. Only
// the first '=' separates key and value: base64 keys end in '='.
func parsePrivateKey(config string) string {
	for _, line := range strings.Split(config, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "PrivateKey" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// commandTimeout bounds every wg, wg-quick and ip command, so a hung tool
// cannot block a request or a reconciler tick forever (replaced in tests).
var commandTimeout = 30 * time.Second

// hostPrefix runs every wg, wg-quick, ip, systemctl and journalctl command
// in the host's mount, UTS, IPC and network namespaces (the control plane
// runs with pid: host), so the host's own tools run under the host's own
// AppArmor profiles. The container's copies do not work on hosts whose
// profiles attach by path: Ubuntu 26.04's wg-quick profile stopped the
// container's wg-quick from running its busybox readlink. Tests set it nil.
var hostPrefix = defaultHostPrefix

var defaultHostPrefix = []string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"}

// SetHostTools selects where the tools run: on the host (true, the default,
// for the control-plane container) or in this process's own namespaces
// (false: a control plane run outside a container, and tests with fake
// tools on PATH).
func SetHostTools(onHost bool) {
	if onHost {
		hostPrefix = defaultHostPrefix
	} else {
		hostPrefix = nil
	}
}

// command builds a host command that is killed after commandTimeout; call
// cancel once it has finished.
func command(name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	full := append(append(append([]string{}, hostPrefix...), name), args...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	cmd.WaitDelay = time.Second // do not wait for pipes a killed child's children still hold
	return cmd, cancel
}

// run runs a host command and returns its trimmed combined output (replaced
// in tests).
var run = func(name string, args ...string) (string, error) {
	cmd, cancel := command(name, args...)
	defer cancel()
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
