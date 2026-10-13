package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParseSSHDPorts extracts the listening ports from `sshd -T` output.
func ParseSSHDPorts(out string) []uint16 {
	seen := map[uint16]bool{}
	var ports []uint16
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.ToLower(fields[0]) != "port" {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 1 || n > 65535 || seen[uint16(n)] {
			continue
		}
		seen[uint16(n)] = true
		ports = append(ports, uint16(n))
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// ParseRouteDevice returns the interface after "dev" in `ip route get` output,
// e.g. "8.8.8.8 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 0".
func ParseRouteDevice(out string) (string, error) {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			if !ifaceRe.MatchString(fields[i+1]) {
				return "", fmt.Errorf("unexpected interface name %q", fields[i+1])
			}
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no device in route output %q", strings.TrimSpace(out))
}
