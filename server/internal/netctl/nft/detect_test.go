package nft

import (
	"errors"
	"strings"
	"testing"
)

func TestParsers(t *testing.T) {
	ports := ParseSSHDPorts("port 2222\nport 22\naddressfamily any\nport 22\nport 0\n")
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 2222 {
		t.Fatalf("ParseSSHDPorts = %v", ports)
	}
	dev, err := ParseRouteDevice("8.8.8.8 via 192.0.2.1 dev ens3 src 192.0.2.10 uid 0\n    cache\n")
	if err != nil || dev != "ens3" {
		t.Fatalf("ParseRouteDevice = %q, %v", dev, err)
	}
	if dev, err := ParseRouteDevice("8.8.8.8 dev ppp0 src 10.64.0.2 uid 0"); err != nil || dev != "ppp0" {
		t.Fatalf("route without gateway: %q, %v", dev, err)
	}
	if _, err := ParseRouteDevice("RTNETLINK answers: Network is unreachable"); err == nil {
		t.Fatal("missing device must be an error")
	}
}

// Real `sshd -T` output for "Port 22" plus "ListenAddress 0.0.0.0:2200" and
// "ListenAddress [::]:2201": sshd listens only on 2200 and 2201.
const sshdListenAddressOutput = "port 22\naddressfamily any\nlistenaddress 0.0.0.0:2200\nlistenaddress [::]:2201\npermitrootlogin yes\n"

func TestParseSSHDPortsReadsListenAddress(t *testing.T) {
	got := ParseSSHDPorts(sshdListenAddressOutput)
	want := []uint16{22, 2200, 2201}
	if len(got) != len(want) {
		t.Fatalf("ParseSSHDPorts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseSSHDPorts = %v, want %v", got, want)
		}
	}
}

// Real `ss -Htlnp` output with sshd plus an unrelated listener.
const ssOutput = `LISTEN 0      128    0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=3615,fd=4))
LISTEN 0      128       [::]:2201    [::]:* users:(("sshd",pid=3615,fd=3))
LISTEN 0      4096   127.0.0.1:5432 0.0.0.0:* users:(("docker-proxy",pid=99,fd=4))
`

func TestParseSSListenPorts(t *testing.T) {
	got := ParseSSListenPorts(ssOutput)
	if len(got) != 2 || got[0] != 2200 || got[1] != 2201 {
		t.Fatalf("ParseSSListenPorts = %v, want [2200 2201]", got)
	}
}

type hostOutputs map[string]string

func (h hostOutputs) Run(_ string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if out, ok := h[cmd]; ok {
		return out, nil
	}
	return "", errors.New(cmd + ": exit status 127")
}

func TestDetectSSHPorts(t *testing.T) {
	ports, err := DetectSSHPorts(hostOutputs{"sshd -T": sshdListenAddressOutput, "ss -Htlnp": ssOutput})
	if err != nil || len(ports) != 3 || ports[0] != 22 || ports[1] != 2200 || ports[2] != 2201 {
		t.Fatalf("DetectSSHPorts = %v, %v; want [22 2200 2201]", ports, err)
	}
	// sshd -T fails (e.g. /run/sshd missing): live listeners still count, 22 always stays.
	ports, err = DetectSSHPorts(hostOutputs{"ss -Htlnp": ssOutput})
	if err != nil || len(ports) != 3 {
		t.Fatalf("ss-only detection = %v, %v", ports, err)
	}
	if _, err := DetectSSHPorts(hostOutputs{}); err == nil {
		t.Fatal("with no source at all detection must fail closed")
	}
}
