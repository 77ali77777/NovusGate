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
		"iptables -S DOCKER-USER",
	}
	want = append(append(want, dockerUserCalls...), "netfilter-persistent save")
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

// dockerUserCalls are the inserts the hand-over makes into DOCKER-USER, in
// order: traffic between VPN interfaces and Docker's bridges returns to
// Docker's own chains (its isolation stays); all other VPN traffic, which
// table inet novusgate already decided (its forward chain runs first, at
// priority filter - 10), passes Docker's FORWARD policy DROP.
var dockerUserCalls = []string{
	"iptables -I DOCKER-USER 1 -i wg+ -o docker0 -m comment --comment novusgate-docker-user -j RETURN",
	"iptables -I DOCKER-USER 2 -i wg+ -o br-+ -m comment --comment novusgate-docker-user -j RETURN",
	"iptables -I DOCKER-USER 3 -i docker0 -o wg+ -m comment --comment novusgate-docker-user -j RETURN",
	"iptables -I DOCKER-USER 4 -i br-+ -o wg+ -m comment --comment novusgate-docker-user -j RETURN",
	"iptables -I DOCKER-USER 5 -i wg+ -m comment --comment novusgate-docker-user -j ACCEPT",
	"iptables -I DOCKER-USER 6 -o wg+ -m comment --comment novusgate-docker-user -j ACCEPT",
}

// ourDockerUser is how iptables -S lists those rules.
const ourDockerUser = "-A DOCKER-USER -i wg+ -o docker0 -m comment --comment novusgate-docker-user -j RETURN\n" +
	"-A DOCKER-USER -i wg+ -o br-+ -m comment --comment novusgate-docker-user -j RETURN\n" +
	"-A DOCKER-USER -i docker0 -o wg+ -m comment --comment novusgate-docker-user -j RETURN\n" +
	"-A DOCKER-USER -i br-+ -o wg+ -m comment --comment novusgate-docker-user -j RETURN\n" +
	"-A DOCKER-USER -i wg+ -m comment --comment novusgate-docker-user -j ACCEPT\n" +
	"-A DOCKER-USER -o wg+ -m comment --comment novusgate-docker-user -j ACCEPT\n"

// Without an ACCEPT in Docker's filter FORWARD chain (policy DROP), VPN
// traffic table inet novusgate allows (full tunnel to the internet, the
// admin VPN wg0, which has no wg-quick PostUp ACCEPT) is still dropped.
func TestCutoverLetsVPNTrafficThroughDocker(t *testing.T) {
	h := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n",
		"iptables -S DOCKER-USER": "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"}, fail: map[string]bool{}}
	if _, err := CutoverIptables(h); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(h.calls, "\n")
	if !strings.Contains(calls, strings.Join(dockerUserCalls, "\n")) {
		t.Fatalf("calls:\n%s\nwant in order:\n%s", calls, strings.Join(dockerUserCalls, "\n"))
	}
	if !strings.HasSuffix(calls, "netfilter-persistent save") {
		t.Errorf("the rules must be saved for boot:\n%s", calls)
	}
}

// Already in place and in order: nothing is touched.
func TestCutoverDockerUserIsIdempotent(t *testing.T) {
	h := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n",
		"iptables -S DOCKER-USER": "-N DOCKER-USER\n" + ourDockerUser + "-A DOCKER-USER -j RETURN\n"}, fail: map[string]bool{}}
	if _, err := CutoverIptables(h); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.calls {
		if strings.Contains(c, "-I DOCKER-USER") || strings.Contains(c, "-D DOCKER-USER") {
			t.Fatalf("nothing may change: %s", c)
		}
	}
}

// An older or partial set (e.g. the first release's two ACCEPTs) is
// replaced: ours are deleted by their own spec, then all are inserted.
func TestCutoverReplacesPartialDockerUserRules(t *testing.T) {
	old := "-A DOCKER-USER -o wg+ -m comment --comment novusgate-docker-user -j ACCEPT\n" +
		"-A DOCKER-USER -i wg+ -m comment --comment novusgate-docker-user -j ACCEPT\n" +
		"-A DOCKER-USER -s 192.0.2.1/32 -j DROP\n"
	h := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n",
		"iptables -S DOCKER-USER": "-N DOCKER-USER\n" + old}, fail: map[string]bool{}}
	if _, err := CutoverIptables(h); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(h.calls, "\n")
	for _, want := range []string{
		"iptables -D DOCKER-USER -o wg+ -m comment --comment novusgate-docker-user -j ACCEPT",
		"iptables -D DOCKER-USER -i wg+ -m comment --comment novusgate-docker-user -j ACCEPT",
		strings.Join(dockerUserCalls, "\n"),
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "-D DOCKER-USER -s 192.0.2.1/32") {
		t.Error("other rules in DOCKER-USER must stay")
	}
}

// Only a missing chain (Docker not managing iptables) means "nothing to
// do"; any other failure is an error, so the hand-over retries.
func TestCutoverDockerUserErrors(t *testing.T) {
	missing := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n",
		"iptables -S DOCKER-USER": "iptables: No chain/target/match by that name.\n"},
		fail: map[string]bool{"iptables -S DOCKER-USER": true}}
	if _, err := CutoverIptables(missing); err != nil {
		t.Fatalf("a host without DOCKER-USER is not an error: %v", err)
	}
	for _, c := range missing.calls {
		if strings.Contains(c, "-I DOCKER-USER") {
			t.Fatalf("no rule may be added without the chain: %s", c)
		}
	}
	broken := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n",
		"iptables -S DOCKER-USER": "nsenter: failed to execute iptables\n"},
		fail: map[string]bool{"iptables -S DOCKER-USER": true}}
	if _, err := CutoverIptables(broken); err == nil {
		t.Fatal("an iptables failure must be reported, not taken for a missing chain")
	}
	failInsert := &hostTable{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n", "iptables -S DOCKER-USER": "-N DOCKER-USER\n"},
		fail: map[string]bool{dockerUserCalls[0]: true}}
	if _, err := CutoverIptables(failInsert); err == nil {
		t.Fatal("a failed insert must be reported")
	}
}

// Outside nftables mode the ACCEPTs must go: iptables mode filters VPN
// traffic in NOVUSGATE-VPN, and Docker puts its DOCKER-USER jump first, so
// an ACCEPT there would skip every VPN rule.
func TestRemoveVPNThroughDocker(t *testing.T) {
	h := &hostTable{out: map[string]string{"iptables -S DOCKER-USER": "-N DOCKER-USER\n" + ourDockerUser +
		"-A DOCKER-USER -s 192.0.2.1/32 -j DROP\n"}, fail: map[string]bool{}}
	n, err := RemoveVPNThroughDocker(h)
	if err != nil || n != 6 {
		t.Fatalf("RemoveVPNThroughDocker = %d, %v; want 6", n, err)
	}
	calls := strings.Join(h.calls, "\n")
	if strings.Contains(calls, "192.0.2.1") || !strings.HasSuffix(calls, "netfilter-persistent save") {
		t.Fatalf("only ours are removed, then saved:\n%s", calls)
	}
	none := &hostTable{out: map[string]string{"iptables -S DOCKER-USER": "-N DOCKER-USER\n"}, fail: map[string]bool{}}
	if n, err := RemoveVPNThroughDocker(none); err != nil || n != 0 || strings.Contains(strings.Join(none.calls, "\n"), "save") {
		t.Fatalf("nothing to remove: %d, %v, %v", n, err, none.calls)
	}
}
