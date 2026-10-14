package rest

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/shared/models"
)

const f2bStatus = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"
const f2bJail = "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total failed:\t5\n|  `- File list:\t/var/log/auth.log\n`- Actions\n   |- Currently banned:\t1\n   |- Total banned:\t2\n   `- Banned IP list:\t203.0.113.9\n"
const iptablesInput = "Chain INPUT (policy DROP)\nnum  target     prot opt source               destination\n1    DROP       all  --  203.0.113.9          0.0.0.0/0\n"

// TestContractHost freezes responses that depend on host commands (stubbed)
// before they move from maps to DTOs.
func TestContractHost(t *testing.T) {
	s, st, stub := newContractServer(t)
	seed := seedContract(t, st)
	for cmd, out := range map[string]string{
		"fail2ban-client --version":                         "Fail2Ban v1.0.2",
		"fail2ban-client status":                            f2bStatus,
		"fail2ban-client status sshd":                       f2bJail,
		"fail2ban-client get sshd bantime":                  "3600",
		"fail2ban-client get sshd maxretry":                 "3",
		"fail2ban-client get sshd findtime":                 "",
		"fail2ban-client set sshd banip 198.51.100.7":       "1",
		"fail2ban-client set sshd unbanip 198.51.100.7":     "1",
		"fail2ban-client set sshd bantime 7200":             "7200",
		"fail2ban-client set sshd addignoreip 192.0.2.0/24": "",
		"fail2ban-client stop sshd":                         "Jail stopped",
		"fail2ban-client reload":                            "OK",
		"fail2ban-client ping":                              "Server replied: pong",
		"iptables -L INPUT -n --line-numbers":               iptablesInput,
		"tail -n 100 /var/log/fail2ban.log":                 "2026-10-13 10:00:05,200 fail2ban.actions [812]: NOTICE  [sshd] Ban 203.0.113.9\n2026-10-13 11:00:05,300 fail2ban.actions [812]: NOTICE  [sshd] Unban 203.0.113.9\n",
	} {
		stub.out[cmd] = out
	}
	origExists := fail2banLogExists
	t.Cleanup(func() { fail2banLogExists = origExists })
	fail2banLogExists = func(string) bool { return true }
	n, node := seed.network.ID, seed.node.ID
	cases := []struct {
		name, method, path, body string
		spec                     bool // false: status or body not documented yet
	}{
		{"f2b_status", "GET", "/api/v1/system/fail2ban/status", "", true},
		{"f2b_logs", "GET", "/api/v1/system/fail2ban/logs", "", true},
		{"f2b_ban", "POST", "/api/v1/system/fail2ban/ban", `{"jail":"sshd","ip":"198.51.100.7"}`, true},
		{"f2b_unban", "POST", "/api/v1/system/fail2ban/unban", `{"jail":"sshd","ip":"198.51.100.7"}`, true},
		{"f2b_jail_settings", "GET", "/api/v1/system/fail2ban/jail/settings", "", true},
		{"f2b_jail_settings_update", "PUT", "/api/v1/system/fail2ban/jail/settings", `{"jail":"sshd","bantime":"7200"}`, true},
		{"f2b_jail_settings_partial", "PUT", "/api/v1/system/fail2ban/jail/settings", `{"jail":"sshd","bantime":"7200","maxretry":"9"}`, true},
		{"f2b_whitelist_update", "PUT", "/api/v1/system/fail2ban/whitelist", `{"jail":"sshd","action":"add","ip":"192.0.2.0/24"}`, true},
		{"f2b_permanent_bans", "GET", "/api/v1/system/fail2ban/permanent-bans", "", true},
		{"f2b_jail_control", "POST", "/api/v1/system/fail2ban/jail/control", `{"jail":"sshd","action":"stop"}`, true},
		{"f2b_reload", "POST", "/api/v1/system/fail2ban/reload", "", true},
		{"f2b_ping", "GET", "/api/v1/system/fail2ban/ping", "", true},
		{"host_debug_wireguard", "GET", "/api/v1/debug/wireguard/" + n, "", true},
		{"host_debug_wireguard_missing", "GET", "/api/v1/debug/wireguard/00000000-0000-4000-8000-000000000000", "", false},
		{"host_checkin", "POST", "/api/v1/nodes/" + node + "/checkin", `{"node_info":{"os":"linux","arch":"amd64","hostname":"edge-1"}}`, true},
		{"host_password", "PUT", "/api/v1/auth/password", `{"username":"contract-user","oldPassword":"contract-pw-1","newPassword":"contract-pw-2"}`, true},
		{"host_server_create", "POST", "/api/v1/networks/" + n + "/servers", `{"name":"contract-srv"}`, true},
	}
	for _, c := range cases {
		rec := callAs(t, s, c.method, c.path, c.body, true)
		assertContract(t, c.name, rec)
		if c.spec {
			assertMatchesSpec(t, s, c.method, c.path, rec)
		}
	}

	// The other branches: fail2ban missing, log missing, ping failing.
	delete(stub.out, "fail2ban-client --version")
	delete(stub.out, "fail2ban-client ping")
	fail2banLogExists = func(string) bool { return false }
	for _, c := range []struct{ name, path string }{
		{"f2b_status_missing", "/api/v1/system/fail2ban/status"},
		{"f2b_logs_missing", "/api/v1/system/fail2ban/logs"},
		{"f2b_ping_down", "/api/v1/system/fail2ban/ping"},
	} {
		rec := callAs(t, s, "GET", c.path, "", true)
		assertContract(t, c.name, rec)
		assertMatchesSpec(t, s, "GET", c.path, rec)
	}
}

// TestContractFirewall freezes the firewall v1 (nft adapters) and v2
// responses through the engine test server.
func TestContractFirewall(t *testing.T) {
	newContractServer(t) // empties networks, so the compiled ruleset is deterministic
	s, _ := newEngineServer(t, firewall.ModeNft)
	ctx := context.Background()
	key := func(c string) string { return strings.Repeat(c, 43) + "=" }
	nw := &models.Network{Name: "contract-fw", CIDR: "10.23.0.0/24", ServerPrivateKey: key("f"),
		ServerPublicKey: key("F"), InterfaceName: "wg94", ListenPort: 51994}
	if err := s.store.CreateNetwork(ctx, nw); err != nil {
		t.Fatal(err)
	}
	nd := &models.Node{NetworkID: nw.ID, Name: "fw-node", VirtualIP: net.ParseIP("10.23.0.5"),
		PublicKey: key("G"), Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := s.store.CreateNode(ctx, nd); err != nil {
		t.Fatal(err)
	}
	run := func(name, method, path, body string) []byte {
		t.Helper()
		rec := call(t, s, method, path, body)
		assertContract(t, name, rec)
		assertMatchesSpec(t, s, method, path, rec)
		return rec.Body.Bytes()
	}
	run("fw_v2_state", "GET", "/api/v1/firewall/v2/state", "")
	run("fw_v2_preview", "GET", "/api/v1/firewall/v2/preview", "")
	run("fw_port_open", "POST", "/api/v1/firewall/host/port/open", `{"port":8444,"protocol":"tcp"}`)
	run("fw_ip_block", "POST", "/api/v1/firewall/host/ip/block", `{"ip":"192.0.2.66"}`)
	run("fw_ip_allow", "POST", "/api/v1/firewall/host/ip/allow", `{"ip":"192.0.2.77"}`)
	run("fw_host_rules", "GET", "/api/v1/firewall/host/rules", "")
	run("fw_port_close", "POST", "/api/v1/firewall/host/port/close", `{"port":8444,"protocol":"tcp"}`)
	run("fw_permanent_ban", "POST", "/api/v1/system/fail2ban/ban", `{"jail":"sshd","ip":"192.0.2.88","permanent":true}`)
	run("fw_permanent_bans", "GET", "/api/v1/system/fail2ban/permanent-bans", "")
	run("fw_permanent_ban_remove", "DELETE", "/api/v1/system/fail2ban/permanent-bans", `{"ip":"192.0.2.88"}`)
	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/open", `{"port":8445,"protocol":"tcp"}`); rec.Code != 200 {
		t.Fatalf("open 8445 = %d %s", rec.Code, rec.Body)
	}
	rule, _ := findRule(inputRules(t, s), "tcp", "8445")
	run("fw_rule_delete", "POST", "/api/v1/firewall/host/rules/delete", `{"chain":"INPUT","line_number":`+itoa(rule.Number)+`}`)
	run("fw_reset", "POST", "/api/v1/firewall/host/reset", "")
	run("fw_vpn_apply", "POST", "/api/v1/firewall/vpn/apply", "")
	run("fw_v2_service_now", "POST", "/api/v1/firewall/v2/services?confirm=false", `{"protocol":"tcp","port_from":9443}`)
	run("fw_v2_egress_on", "PUT", "/api/v1/firewall/v2/egress/"+nd.ID+"?confirm=false", "")
	run("fw_v2_egress_off", "DELETE", "/api/v1/firewall/v2/egress/"+nd.ID+"?confirm=false", "")
	// The pending change ID is random: read it, then mask it before the snapshot.
	rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9444}`)
	var pending struct {
		Pending struct{ ID string } `json:"pending"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pending); err != nil || pending.Pending.ID == "" {
		t.Fatalf("pending service = %d %s", rec.Code, rec.Body)
	}
	masked := strings.ReplaceAll(rec.Body.String(), pending.Pending.ID, "<pending-id>")
	rec.Body.Reset()
	rec.Body.WriteString(masked)
	assertContract(t, "fw_v2_service_pending", rec)
	assertMatchesSpec(t, s, "POST", "/api/v1/firewall/v2/services", rec)
	run("fw_v2_confirm", "POST", "/api/v1/firewall/v2/confirm/"+pending.Pending.ID, "")
	run("fw_v2_state_after", "GET", "/api/v1/firewall/v2/state", "")
}

// TestSystemInfoShape pins /system/info's keys and JSON types; its values
// come from /proc and vary between machines.
func TestSystemInfoShape(t *testing.T) {
	s, _, stub := newContractServer(t)
	stub.out["df -B1 /"] = "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 1000 400 600 40% /\n"
	rec := callAs(t, s, "GET", "/api/v1/system/info", "", true)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	always := map[string]string{"cpu_cores": "number", "hostname": "string", "memory_total": "number", "memory_free": "number",
		"memory_available": "number", "memory_used": "number", "memory_buffers": "number", "memory_cached": "number",
		"disk_total": "number", "disk_used": "number", "disk_free": "number"}
	optional := map[string]string{"cpu_model": "string", "load_1m": "string", "load_5m": "string", "load_15m": "string", "uptime_seconds": "number"}
	kind := func(v any) string {
		switch v.(type) {
		case string:
			return "string"
		case float64:
			return "number"
		}
		return "other"
	}
	for k, want := range always {
		if v, ok := body[k]; !ok || kind(v) != want {
			t.Errorf("%s = %v (%s), want a %s", k, v, kind(v), want)
		}
	}
	for k, v := range body {
		want, ok := always[k]
		if !ok {
			want, ok = optional[k]
		}
		if !ok || kind(v) != want {
			t.Errorf("unexpected key or type %s = %v", k, v)
		}
	}
}
