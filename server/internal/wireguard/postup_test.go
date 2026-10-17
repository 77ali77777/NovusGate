package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ubuntu 26.04's wg-quick AppArmor profile does not let wg-quick run awk:
// the old PostUp "-o $(ip route get 8.8.8.8 | awk ...)" got an empty
// interface, iptables failed ("Bad argument `MASQUERADE'") and wg-quick
// removed the interface. The internet interface is now found by the control
// plane and written into the config as a plain name.

const legacyPostUp = "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE\n" +
	"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE\n"

func TestServerConfigNamesTheInternetInterface(t *testing.T) {
	conf := NewConfigGenerator().GenerateServerConfig("KEY", 51821, "10.10.0.1/24", "eth0")
	if strings.Contains(conf, "$(") || strings.Contains(conf, "awk") {
		t.Fatalf("no shell substitution may be left:\n%s", conf)
	}
	for _, want := range []string{
		"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n",
		"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
}

// Unknown (or not a plain interface name, which would be shell in PostUp):
// forwarding is still allowed, only the masquerade is left out.
func TestServerConfigWithoutAnInternetInterface(t *testing.T) {
	for _, egress := range []string{"", "eth0; reboot", "$(id)"} {
		conf := NewConfigGenerator().GenerateServerConfig("KEY", 51821, "10.10.0.1/24", egress)
		if strings.Contains(conf, "MASQUERADE") || strings.Contains(conf, "reboot") || strings.Contains(conf, "$(") {
			t.Errorf("egress %q:\n%s", egress, conf)
		}
		if !strings.Contains(conf, "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT\n") {
			t.Errorf("egress %q: forwarding must stay:\n%s", egress, conf)
		}
	}
}

func TestEgressInterfaceFromTheHostsRoute(t *testing.T) {
	h := fakeHost(t, false, false)
	h.out["ip -o route get 8.8.8.8"] = "8.8.8.8 via 172.31.1.1 dev eth0 src 2.28.205.152 uid 0 \\    cache"
	if got := EgressInterface(); got != "eth0" {
		t.Fatalf("EgressInterface = %q", got)
	}
	h.fail["ip -o route get 8.8.8.8"] = true
	if got := EgressInterface(); got != "" {
		t.Fatalf("no route must give \"\", got %q", got)
	}
}

// A config written by an older version gets the plain name before its unit
// starts; other lines (keys, peers) stay as they are.
func TestStartRewritesALegacyPostUp(t *testing.T) {
	h := fakeHost(t, false, false)
	h.fail[isActive] = true
	h.out["ip -o route get 8.8.8.8"] = "8.8.8.8 via 172.31.1.1 dev ens3 src 203.0.113.5 uid 0"
	m := NewManager("wg3")
	m.ConfigPath = filepath.Join(t.TempDir(), "wg3.conf")
	body := "[Interface]\nPrivateKey = KEY\nAddress = 10.10.0.1/24\nListenPort = 51821\nSaveConfig = false\n" + legacyPostUp
	if err := os.WriteFile(m.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Up(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(m.ConfigPath)
	if strings.Contains(string(got), "awk") || !strings.Contains(string(got), "-o ens3 -j MASQUERADE") ||
		!strings.Contains(string(got), "PrivateKey = KEY\nAddress = 10.10.0.1/24\n") {
		t.Fatalf("config after start:\n%s", got)
	}
	if info, _ := os.Stat(m.ConfigPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("the config must stay 0600, got %v", info.Mode().Perm())
	}
}
