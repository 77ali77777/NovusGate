package hostadmin

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// fakeRunner answers commands from a table and records them.
type fakeRunner struct {
	out    map[string]string
	fail   map[string]error
	calls  []string
	stdins map[string]string
}

func (f *fakeRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if f.stdins == nil {
		f.stdins = map[string]string{}
	}
	f.stdins[cmd] = stdin
	if err := f.fail[cmd]; err != nil {
		return f.out[cmd], err
	}
	return f.out[cmd], nil
}

func (f *fakeRunner) ran(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestServicesListsAllowedUnits(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"systemctl list-units wg-quick@* --all --no-legend --plain": "wg-quick@wg0.service loaded active exited WireGuard via wg-quick(8) for wg0\nwg-quick@wg1.service loaded failed failed WireGuard via wg-quick(8) for wg1\n",
		"systemctl is-active docker":                                "active\n",
		"systemctl is-active fail2ban":                              "inactive\n",
	}, fail: map[string]error{"systemctl is-active fail2ban": errors.New("exit status 3")}}
	got, err := Services(r)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"docker": "active", "fail2ban": "inactive", "wg-quick@wg0": "active", "wg-quick@wg1": "failed"}
	if len(got) != len(want) {
		t.Fatalf("services = %+v", got)
	}
	for _, s := range got {
		if want[s.Name] != s.State {
			t.Errorf("%s = %q, want %q", s.Name, s.State, want[s.Name])
		}
	}
}

func TestRestartOnlyAllowedUnits(t *testing.T) {
	r := &fakeRunner{}
	for _, u := range []string{"docker", "fail2ban", "wg-quick@wg3"} {
		if err := Restart(r, u); err != nil {
			t.Errorf("restart %s: %v", u, err)
		}
	}
	for _, u := range []string{"ssh", "wg-quick@wg0;reboot", "wg-quick@../x", "docker.service", ""} {
		if err := Restart(r, u); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("restart %q = %v, want ErrNotAllowed", u, err)
		}
	}
	if !r.ran("systemctl restart wg-quick@wg3") || r.ran("systemctl restart ssh") {
		t.Fatalf("calls = %v", r.calls)
	}
}

func TestSysctlValidation(t *testing.T) {
	ok := map[string]string{
		"net.ipv4.ip_forward":             "1",
		"net.ipv4.conf.all.rp_filter":     "2",
		"net.netfilter.nf_conntrack_max":  "262144",
		"net.ipv4.tcp_congestion_control": "bbr",
		"net.core.default_qdisc":          "fq",
	}
	if err := ValidateSysctl(ok); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for name, bad := range map[string]map[string]string{
		"unknown key":     {"kernel.panic": "1"},
		"forward 2":       {"net.ipv4.ip_forward": "2"},
		"rp_filter 3":     {"net.ipv4.conf.all.rp_filter": "3"},
		"conntrack text":  {"net.netfilter.nf_conntrack_max": "lots"},
		"conntrack small": {"net.netfilter.nf_conntrack_max": "10"},
		"unknown cc":      {"net.ipv4.tcp_congestion_control": "reno; reboot"},
		"unknown qdisc":   {"net.core.default_qdisc": "pfifo\n"},
		"empty":           {},
	} {
		if err := ValidateSysctl(bad); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// Applying writes the managed file, loads it and arms a rollback that
// restores the old values and the old file unless it is confirmed.
func TestSysctlApplyArmsRollback(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"sysctl -n net.ipv4.ip_forward":             "0\n",
		"sysctl -n net.ipv4.tcp_congestion_control": "cubic\n",
		"cat " + SysctlFile:                         "# old\nnet.ipv4.ip_forward = 0\n",
	}}
	s := &Sysctl{Runner: r, Timeout: 90 * time.Second}
	if err := s.Apply(map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.tcp_congestion_control": "bbr"}); err != nil {
		t.Fatal(err)
	}
	file := r.stdins["tee "+SysctlFile]
	if !strings.Contains(file, "net.ipv4.ip_forward = 1\n") || !strings.Contains(file, "net.ipv4.tcp_congestion_control = bbr\n") {
		t.Fatalf("written file:\n%s", file)
	}
	if !r.ran("sysctl -p " + SysctlFile) {
		t.Fatalf("not loaded: %v", r.calls)
	}
	rollback := r.stdins["tee "+SysctlRollbackScript]
	for _, s := range []string{"sysctl -w net.ipv4.ip_forward=0", "sysctl -w net.ipv4.tcp_congestion_control=cubic", "# old"} {
		if !strings.Contains(rollback, s) {
			t.Errorf("rollback script lacks %q:\n%s", s, rollback)
		}
	}
	if !r.ran("systemd-run --unit=novusgate-sysctl-rollback --on-active=90s --timer-property=AccuracySec=1s sh " + SysctlRollbackScript) {
		t.Fatalf("rollback timer not armed: %v", r.calls)
	}
	r.out[timerActive] = "active\n" // the timer waits
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl stop novusgate-sysctl-rollback.timer") {
		t.Fatalf("confirm did not disarm: %v", r.calls)
	}
}

// A failed load rolls back at once and reports the error.
func TestSysctlApplyFailureRollsBack(t *testing.T) {
	r := &fakeRunner{
		out:  map[string]string{"sysctl -n net.ipv4.ip_forward": "1\n"},
		fail: map[string]error{"sysctl -p " + SysctlFile: errors.New("invalid argument")},
	}
	s := &Sysctl{Runner: r, Timeout: time.Minute}
	if err := s.Apply(map[string]string{"net.ipv4.ip_forward": "0"}); err == nil {
		t.Fatal("want the load error")
	}
	if !r.ran("sh " + SysctlRollbackScript) {
		t.Fatalf("not rolled back at once: %v", r.calls)
	}
	if r.ran("systemd-run") {
		t.Fatal("no timer after a failed load")
	}
}

func TestHostnameAndTimezoneValidation(t *testing.T) {
	for _, h := range []string{"vpn-hub", "a", "hub01.example.com"} {
		if err := ValidHostname(h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	for _, h := range []string{"", "-hub", "hub_1", "hub;reboot", strings.Repeat("a", 64), "a..b"} {
		if err := ValidHostname(h); err == nil {
			t.Errorf("%q: want an error", h)
		}
	}
	if err := ValidTimezone("Asia/Baku"); err != nil {
		t.Error(err)
	}
	for _, z := range []string{"", "Mars/Olympus", "../etc/passwd", "Asia/Baku;reboot"} {
		if err := ValidTimezone(z); err == nil {
			t.Errorf("%q: want an error", z)
		}
	}
}

func TestSetSystemCommands(t *testing.T) {
	r := &fakeRunner{}
	if err := SetHostname(r, "vpn-hub"); err != nil {
		t.Fatal(err)
	}
	if err := SetTimezone(r, "Asia/Baku", true); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"hostnamectl set-hostname vpn-hub", "timedatectl set-timezone Asia/Baku", "timedatectl set-ntp true"} {
		if !r.ran(c) {
			t.Errorf("missing %q in %v", c, r.calls)
		}
	}
}

func TestSystemInfo(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"hostname":            "vpn-hub\n",
		"timedatectl show":    "Timezone=Asia/Baku\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n",
		"uname -r":            "5.15.0-122-generic\n",
		"cat /etc/os-release": "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\nID=ubuntu\n",
	}}
	got, err := System(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "vpn-hub" || got.Timezone != "Asia/Baku" || !got.NTP || !got.NTPSynchronized ||
		got.Kernel != "5.15.0-122-generic" || got.OS != "Ubuntu 22.04.5 LTS" {
		t.Fatalf("system = %+v", got)
	}
}

func TestUpgradablePackages(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"apt list --upgradable": "Listing...\nopenssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.17]\nlibssl3/jammy-updates 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.17]\n",
	}}
	got, err := Upgradable(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "openssl" || got[0].Version != "3.0.2-0ubuntu1.18" || got[0].From != "3.0.2-0ubuntu1.17" || !got[0].Security {
		t.Fatalf("packages = %+v", got)
	}
	if got[1].Security {
		t.Fatal("libssl3 is not from the security pocket")
	}
}

func TestNetworkView(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"ip -j addr":  `[{"ifname":"eth0"}]`,
		"ip -j route": `[{"dst":"default","gateway":"203.0.113.1"}]`,
		"ip -j link":  `[{"ifname":"eth0","operstate":"UP"}]`,
	}}
	got, err := Network(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got.Addresses), "eth0") || !strings.Contains(string(got.Routes), "203.0.113.1") || !strings.Contains(string(got.Links), "UP") {
		t.Fatalf("network = %+v", got)
	}
	r.out["ip -j addr"] = "not json"
	if _, err := Network(r); err == nil {
		t.Fatal("invalid JSON must be an error")
	}
}

// The rollback script is valid sh (it runs on the host from a systemd timer),
// also when the old file must be written back.
func TestSysctlRollbackScriptIsValidShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	for _, oldFile := range []string{"", "# old\nnet.ipv4.ip_forward = 0\n"} {
		r := &fakeRunner{out: map[string]string{"sysctl -n net.ipv4.ip_forward": "0\n", "cat " + SysctlFile: oldFile}}
		s := &Sysctl{Runner: r, Timeout: time.Minute}
		if err := s.Apply(map[string]string{"net.ipv4.ip_forward": "1"}); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(r.stdins["tee "+SysctlRollbackScript])
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v\n%s\n%s", err, out, r.stdins["tee "+SysctlRollbackScript])
		}
	}
}

const timerActive = "systemctl is-active " + sysctlRollbackUnit + ".timer"

// A second change while one waits for Confirm would overwrite the rollback
// script with the first change's values: it is refused, nothing is written.
func TestSysctlApplyRefusedWhilePending(t *testing.T) {
	r := &fakeRunner{out: map[string]string{timerActive: "active\n"}}
	s := &Sysctl{Runner: r, Timeout: time.Minute}
	if err := s.Apply(map[string]string{"net.ipv4.ip_forward": "1"}); !errors.Is(err, ErrSysctlPending) {
		t.Fatalf("err = %v, want ErrSysctlPending", err)
	}
	if r.ran("tee") || r.ran("sysctl -p") {
		t.Fatalf("a refused change wrote something: %v", r.calls)
	}
}

// Confirm after the timer fired (or with nothing applied) must not report
// success: the host already has the old values back.
func TestSysctlConfirmWithoutPending(t *testing.T) {
	r := &fakeRunner{out: map[string]string{timerActive: "inactive\n"}, fail: map[string]error{timerActive: errors.New("exit status 3")}}
	s := &Sysctl{Runner: r}
	if err := s.Confirm(); !errors.Is(err, ErrSysctlNotPending) {
		t.Fatalf("err = %v, want ErrSysctlNotPending", err)
	}
	if r.ran("systemctl stop") {
		t.Fatal("nothing to stop")
	}
}

// An elapsed transient timer can stay loaded; it is stopped before a new one
// with the same name is armed.
func TestSysctlApplyClearsElapsedTimer(t *testing.T) {
	r := &fakeRunner{out: map[string]string{"sysctl -n net.ipv4.ip_forward": "0\n"}}
	s := &Sysctl{Runner: r, Timeout: time.Minute}
	if err := s.Apply(map[string]string{"net.ipv4.ip_forward": "1"}); err != nil {
		t.Fatal(err)
	}
	stop, arm := -1, -1
	for i, c := range r.calls {
		if c == "systemctl stop "+sysctlRollbackUnit+".timer" {
			stop = i
		}
		if strings.HasPrefix(c, "systemd-run") {
			arm = i
		}
	}
	if stop < 0 || arm < 0 || stop > arm {
		t.Fatalf("stop at %d, arm at %d: %v", stop, arm, r.calls)
	}
	if until, ok := SysctlPendingUntil(); !ok || time.Until(until) <= 0 {
		t.Fatalf("pending until = %v %v", until, ok)
	}
}

// A failed write of the managed file may have left part of it: undo at once.
func TestSysctlFileWriteFailureRollsBack(t *testing.T) {
	r := &fakeRunner{
		out:  map[string]string{"sysctl -n net.ipv4.ip_forward": "0\n"},
		fail: map[string]error{"tee " + SysctlFile: errors.New("no space left on device")},
	}
	s := &Sysctl{Runner: r, Timeout: time.Minute}
	if err := s.Apply(map[string]string{"net.ipv4.ip_forward": "1"}); err == nil {
		t.Fatal("want the write error")
	}
	if !r.ran("sh " + SysctlRollbackScript) {
		t.Fatalf("not rolled back: %v", r.calls)
	}
}

// docker restarts without waiting: it stops this very container.
func TestRestartDockerDoesNotBlock(t *testing.T) {
	r := &fakeRunner{}
	if err := Restart(r, "docker"); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl restart --no-block docker") {
		t.Fatalf("calls = %v", r.calls)
	}
}
