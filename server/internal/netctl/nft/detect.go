package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParseSSHDPorts extracts SSH ports from `sshd -T` output: the "port" lines
// and the port of every "listenaddress" line. With `ListenAddress host:port`
// sshd listens only on that port while still printing "port 22", so the
// listen addresses must be read too.
func ParseSSHDPorts(out string) []uint16 {
	var ports []uint16
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "port":
			ports = appendPort(ports, fields[1])
		case "listenaddress":
			if i := strings.LastIndex(fields[1], ":"); i >= 0 {
				ports = appendPort(ports, fields[1][i+1:])
			}
		}
	}
	return uniqueSorted(ports)
}

// ParseSSListenPorts extracts the ports sshd is listening on from
// `ss -Htlnp` output.
func ParseSSListenPorts(out string) []uint16 {
	var ports []uint16
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.Contains(line, `("sshd",`) {
			continue
		}
		local := fields[3]
		if i := strings.LastIndex(local, ":"); i >= 0 {
			ports = appendPort(ports, local[i+1:])
		}
	}
	return uniqueSorted(ports)
}

// DetectSSHPorts returns every port SSH must stay reachable on: the ports
// from sshd's configuration, the ports sshd is actually listening on, and 22,
// which has always been open. It fails closed when neither source works.
func DetectSSHPorts(r Runner) ([]uint16, error) {
	ports := []uint16{22}
	found := false
	if out, err := r.Run("", "sshd", "-T"); err == nil {
		if p := ParseSSHDPorts(out); len(p) > 0 {
			ports, found = append(ports, p...), true
		}
	}
	if out, err := r.Run("", "ss", "-Htlnp"); err == nil {
		if p := ParseSSListenPorts(out); len(p) > 0 {
			ports, found = append(ports, p...), true
		}
	}
	if !found {
		return nil, fmt.Errorf("cannot detect SSH ports: neither `sshd -T` nor `ss -Htlnp` reported sshd")
	}
	return uniqueSorted(ports), nil
}

func appendPort(ports []uint16, s string) []uint16 {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return ports
	}
	return append(ports, uint16(n))
}

func uniqueSorted(ports []uint16) []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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
