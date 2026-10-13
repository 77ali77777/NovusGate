package firewall

import (
	"errors"
	"strings"
	"testing"
)

// hostTable answers commands from a table and records every call.
type hostTable struct {
	out   map[string]string
	fail  map[string]bool
	calls []string
}

func (f *hostTable) Run(_ string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if f.fail[cmd] {
		return f.out[cmd], errors.New("exit status 1")
	}
	return f.out[cmd], nil
}

func readyHost() *hostTable {
	return &hostTable{out: map[string]string{
		"nft --version": "nftables v1.0.9 (Old Doc Yak #3)\n",
		"systemctl is-enabled novusgate-firewall.service": "enabled\n",
		"iptables -V": "iptables v1.8.10 (nf_tables)\n",
	}, fail: map[string]bool{}}
}

func TestCheckHostAcceptsReadyHost(t *testing.T) {
	if err := CheckHost(readyHost()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckHostRefusesUnreadyHosts(t *testing.T) {
	cases := map[string]func(h *hostTable){
		"nft missing": func(h *hostTable) { h.fail["nft --version"] = true },
		"nft 0.9.3":   func(h *hostTable) { h.out["nft --version"] = "nftables v0.9.3 (Topsy)\n" },
		"nft 1.0.1":   func(h *hostTable) { h.out["nft --version"] = "nftables v1.0.1 (Fearless Fosdick #3)\n" },
		"unit disabled": func(h *hostTable) {
			h.out["systemctl is-enabled novusgate-firewall.service"] = "disabled\n"
			h.fail["systemctl is-enabled novusgate-firewall.service"] = true
		},
		"legacy iptables": func(h *hostTable) { h.out["iptables -V"] = "iptables v1.8.4 (legacy)\n" },
		"no iptables":     func(h *hostTable) { h.fail["iptables -V"] = true },
	}
	for name, mutate := range cases {
		h := readyHost()
		mutate(h)
		if err := CheckHost(h); err == nil {
			t.Errorf("%s: CheckHost must refuse", name)
		}
	}
	h := readyHost()
	h.out["nft --version"] = "nftables v1.0.2 (Lester Gooch)\n"
	if err := CheckHost(h); err != nil {
		t.Errorf("nft 1.0.2 is the supported minimum: %v", err)
	}
}

func TestCutoverAcceptsFirstThenDeletesPanelRules(t *testing.T) {
	h := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT DROP\n" +
		"-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n" +
		"-A INPUT -i lo -j ACCEPT\n" +
		`-A INPUT -p tcp -m tcp --dport 443 -m comment --comment "panel \"web\" port" -j ACCEPT` + "\n" +
		"-A INPUT -s 198.51.100.9/32 -j DROP\n" +
		"-A INPUT -s 203.0.113.4/32 -j REJECT --reject-with icmp-port-unreachable\n" +
		"-A INPUT -j CROWDSEC_CHAIN\n"}, fail: map[string]bool{}}
	n, err := CutoverIptables(h)
	if err != nil || n != 3 {
		t.Fatalf("CutoverIptables = %d, %v", n, err)
	}
	// Rules are deleted by their own spec, so a fail2ban jump inserted or
	// removed meanwhile can never shift what is deleted; REJECT bans and
	// jumps to other tools' chains stay.
	want := []string{
		"iptables -P INPUT ACCEPT",
		"iptables -S INPUT",
		"iptables -D INPUT -i lo -j ACCEPT",
		`iptables -D INPUT -p tcp -m tcp --dport 443 -m comment --comment panel "web" port -j ACCEPT`,
		"iptables -D INPUT -s 198.51.100.9/32 -j DROP",
		"netfilter-persistent save",
	}
	if strings.Join(h.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(h.calls, "\n"), strings.Join(want, "\n"))
	}
}

// The quoted comment must reach iptables as one argument.
func TestSplitIptablesArgs(t *testing.T) {
	got := splitIptablesArgs(`-p tcp -m comment --comment "panel \"web\" port" -j ACCEPT`)
	want := []string{"-p", "tcp", "-m", "comment", "--comment", `panel "web" port`, "-j", "ACCEPT"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

func TestCutoverIsIdempotentAndKeepsFail2ban(t *testing.T) {
	h := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n" +
		"-A INPUT -p tcp -m multiport --dports 22,2222 -j f2b-sshd\n"}, fail: map[string]bool{}}
	if n, err := CutoverIptables(h); err != nil || n != 0 {
		t.Fatalf("second hand-over = %d, %v", n, err)
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "iptables -D") {
			t.Fatalf("fail2ban jumps must stay: %s", c)
		}
	}
}

func TestCutoverStopsWhenPolicyCannotBeChanged(t *testing.T) {
	h := &hostTable{out: map[string]string{}, fail: map[string]bool{"iptables -P INPUT ACCEPT": true}}
	if _, err := CutoverIptables(h); err == nil || len(h.calls) != 1 {
		t.Fatalf("no rule may be deleted while INPUT still drops (err=%v, calls=%v)", err, h.calls)
	}
}

func TestCutoverToleratesMissingPersistence(t *testing.T) {
	h := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT DROP\n"},
		fail: map[string]bool{"netfilter-persistent save": true}}
	if _, err := CutoverIptables(h); err != nil {
		t.Fatalf("the next start repeats the hand-over; save failure is only logged: %v", err)
	}
}
