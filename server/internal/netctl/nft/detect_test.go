package nft

import "testing"

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
