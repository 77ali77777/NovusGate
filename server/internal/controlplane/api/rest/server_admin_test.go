package rest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// hostFake answers host commands for the server administration routes.
type hostFake struct {
	out   map[string]string
	calls []string
}

func (h *hostFake) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	h.calls = append(h.calls, cmd)
	return h.out[cmd], nil
}

func (h *hostFake) ran(cmd string) bool {
	for _, c := range h.calls {
		if c == cmd {
			return true
		}
	}
	return false
}

func newServerAdmin(t *testing.T) (*Server, *hostFake) {
	t.Helper()
	s, _, _ := newContractServer(t)
	h := &hostFake{out: map[string]string{
		"hostname":                      "vpn-hub\n",
		"timedatectl show":              "Timezone=UTC\nNTP=yes\nNTPSynchronized=yes\n",
		"uname -r":                      "5.15.0\n",
		"ip -j addr":                    `[{"ifname":"eth0","operstate":"UP","addr_info":[{"family":"inet","local":"203.0.113.5","prefixlen":24}]}]`,
		"ip -j route":                   `[{"dst":"default","gateway":"203.0.113.1","dev":"eth0"}]`,
		"ip -j link":                    `[{"ifname":"eth0","operstate":"UP"}]`,
		"sysctl -n net.ipv4.ip_forward": "1\n",
		"apt list --upgradable":         "Listing...\n",
		"systemctl list-units wg-quick@* --all --no-legend --plain": "",
	}}
	s.host = h
	return s, h
}

// Changes to the server need a fresh password check (step-up, 5 minutes);
// reads do not.
func TestServerChangesNeedStepUp(t *testing.T) {
	s, h := newServerAdmin(t)
	if rec := callAs(t, s, "GET", "/api/v1/server/system", "", true); rec.Code != 200 || !strings.Contains(rec.Body.String(), "vpn-hub") {
		t.Fatalf("system = %d %s", rec.Code, rec.Body)
	}
	rec := callAs(t, s, "PUT", "/api/v1/server/system/hostname", `{"hostname":"hub2"}`, true)
	if rec.Code != 403 || errorCode(t, rec.Body.Bytes()) != "step_up_required" {
		t.Fatalf("without step-up = %d %s", rec.Code, rec.Body)
	}
	if h.ran("hostnamectl set-hostname hub2") {
		t.Fatal("nothing may run without step-up")
	}
	if rec := callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"wrong"}`, true); rec.Code != 400 || errorCode(t, rec.Body.Bytes()) != "invalid_password" {
		t.Fatalf("step-up with a wrong password = %d", rec.Code)
	}
	if rec := callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"contract-pw-1"}`, true); rec.Code != 204 {
		t.Fatalf("step-up = %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/server/system/hostname", `{"hostname":"hub2"}`, true); rec.Code != 200 {
		t.Fatalf("after step-up = %d %s", rec.Code, rec.Body)
	}
	if !h.ran("hostnamectl set-hostname hub2") {
		t.Fatalf("calls = %v", h.calls)
	}
	// Five minutes later the step-up has expired.
	saved := authNow
	authNow = func() time.Time { return time.Now().Add(6 * time.Minute) }
	defer func() { authNow = saved }()
	if rec := callAs(t, s, "PUT", "/api/v1/server/system/hostname", `{"hostname":"hub3"}`, true); rec.Code != 403 {
		t.Fatalf("after expiry = %d", rec.Code)
	}
}

func TestServerAdminValidation(t *testing.T) {
	s, h := newServerAdmin(t)
	callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"contract-pw-1"}`, true)
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/v1/server/system/hostname", `{"hostname":"bad;reboot"}`},
		{"PUT", "/api/v1/server/system/timezone", `{"timezone":"Mars/Olympus","ntp":true}`},
		{"PUT", "/api/v1/server/sysctl", `{"values":{"kernel.panic":"1"}}`},
		{"POST", "/api/v1/server/services/ssh/restart", ``},
		{"POST", "/api/v1/server/reboot", `{"confirm":"yes"}`},
		{"POST", "/api/v1/server/packages/upgrade", `{"confirm":"reboot"}`},
	} {
		if rec := callAs(t, s, c.method, c.path, c.body, true); rec.Code != 400 {
			t.Errorf("%s %s %s = %d %s, want 400", c.method, c.path, c.body, rec.Code, rec.Body)
		}
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "hostnamectl") || strings.HasPrefix(c, "systemctl restart") || strings.HasPrefix(c, "systemctl reboot") || strings.HasPrefix(c, "apt-get") {
			t.Errorf("a rejected request ran %q", c)
		}
	}
}

func TestServerAdminReadsAndChanges(t *testing.T) {
	s, h := newServerAdmin(t)
	callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"contract-pw-1"}`, true)
	for _, p := range []string{"/api/v1/server/services", "/api/v1/server/sysctl", "/api/v1/server/packages", "/api/v1/server/network"} {
		rec := callAs(t, s, "GET", p, "", true)
		if rec.Code != 200 {
			t.Errorf("GET %s = %d %s", p, rec.Code, rec.Body)
		}
		assertMatchesSpec(t, s, "GET", p, rec)
	}
	rec := callAs(t, s, "PUT", "/api/v1/server/sysctl", `{"values":{"net.ipv4.ip_forward":"1"}}`, true)
	if rec.Code != 200 {
		t.Fatalf("sysctl = %d %s", rec.Code, rec.Body)
	}
	var pending SysctlChangeResponse
	json.Unmarshal(rec.Body.Bytes(), &pending)
	if pending.ConfirmWithin <= 0 || !h.ran("sysctl -p /etc/sysctl.d/90-novusgate.conf") {
		t.Fatalf("pending = %+v calls %v", pending, h.calls)
	}
	if rec := callAs(t, s, "POST", "/api/v1/server/sysctl/confirm", "", true); rec.Code != 204 {
		t.Fatalf("confirm = %d", rec.Code)
	}
	if rec := callAs(t, s, "POST", "/api/v1/server/services/fail2ban/restart", "", true); rec.Code != 204 || !h.ran("systemctl restart fail2ban") {
		t.Fatalf("restart = %d %v", rec.Code, h.calls)
	}
	if rec := callAs(t, s, "PUT", "/api/v1/server/system/timezone", `{"timezone":"Asia/Baku","ntp":true}`, true); rec.Code != 200 || !h.ran("timedatectl set-timezone Asia/Baku") {
		t.Fatalf("timezone = %d %v", rec.Code, h.calls)
	}
	if rec := callAs(t, s, "POST", "/api/v1/server/reboot", `{"confirm":"reboot"}`, true); rec.Code != 202 {
		t.Fatalf("reboot = %d %s", rec.Code, rec.Body)
	}
}

// Server administration is for admins only, reads included.
func TestServerAdminIsAdminOnly(t *testing.T) {
	s, st, _ := newContractServer(t)
	operator := roleSession(t, st, "srv-operator", "operator")
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/server/system"},
		{"GET", "/api/v1/server/network"},
		{"POST", "/api/v1/server/reboot"},
	} {
		if rec := callWith(t, s, operator, c.method, c.path, `{}`); rec.Code != 403 {
			t.Errorf("operator %s %s = %d", c.method, c.path, rec.Code)
		}
	}
}

// An upgrade runs in the background; its output and result are kept, and
// a second one is refused while it runs.
func TestServerUpgradeJob(t *testing.T) {
	s, h := newServerAdmin(t)
	h.out["apt-get update"] = "Reading package lists...\n"
	h.out["env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade"] = "0 upgraded\n"
	callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"contract-pw-1"}`, true)
	if rec := callAs(t, s, "POST", "/api/v1/server/packages/upgrade", `{"confirm":"upgrade"}`, true); rec.Code != 202 {
		t.Fatalf("upgrade = %d %s", rec.Code, rec.Body)
	}
	var job UpgradeJob
	for i := 0; i < 50; i++ {
		json.Unmarshal(callAs(t, s, "GET", "/api/v1/server/packages/upgrade", "", true).Body.Bytes(), &job)
		if !job.Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job.Running || !job.OK || !strings.Contains(job.Output, "0 upgraded") || job.FinishedAt == nil {
		t.Fatalf("job = %+v", job)
	}
}

// A wrong step-up password is 400, not 401 (a 401 logs the panel out), and
// guessing is limited per user: after 5 failures even the right password
// waits.
func TestStepUpGuessingIsLimited(t *testing.T) {
	saved := stepUpLimit
	stepUpLimit = newLoginLimiter(5, 15*time.Minute)
	defer func() { stepUpLimit = saved }()
	s, _ := newServerAdmin(t)
	for i := 0; i < 5; i++ {
		if rec := callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"wrong"}`, true); rec.Code != 400 {
			t.Fatalf("attempt %d = %d", i, rec.Code)
		}
	}
	rec := callAs(t, s, "POST", "/api/v1/auth/step-up", `{"password":"contract-pw-1"}`, true)
	if rec.Code != 429 || errorCode(t, rec.Body.Bytes()) != "too_many_attempts" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("after 5 failures = %d %s", rec.Code, rec.Body)
	}
}
