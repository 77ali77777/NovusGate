package rest

import (
	"fmt"
	"strings"
	"testing"
)

const sampleF2BLog = `2026-10-13 10:00:01,100 fail2ban.filter  [812]: INFO    [sshd] Found 203.0.113.9 - 2026-10-13 10:00:01
2026-10-13 10:00:05,200 fail2ban.actions [812]: NOTICE  [sshd] Ban 203.0.113.9
2026-10-13 11:00:05,300 fail2ban.actions [812]: NOTICE  [sshd] Unban 203.0.113.9
2026-10-13 11:30:00,400 fail2ban.actions [812]: NOTICE  [recidive] Ban 198.51.100.7
2026-10-13 12:00:00,500 fail2ban.actions [812]: NOTICE  [sshd] Restore Ban 192.0.2.4
`

func TestFail2BanLogAction(t *testing.T) {
	for line, want := range map[string]string{
		"... NOTICE  [sshd] Unban 203.0.113.9":       "unban",
		"... NOTICE  [sshd] Ban 203.0.113.9":         "ban",
		"... NOTICE  [sshd] Restore Ban 192.0.2.4":   "ban",
		"... INFO    [sshd] Found 203.0.113.9 - ...": "found",
		"... INFO    Jail 'sshd' started":            "",
	} {
		if got := fail2banLogAction(line); got != want {
			t.Errorf("fail2banLogAction(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseFail2BanHistory(t *testing.T) {
	all := parseFail2BanHistory(strings.NewReader(sampleF2BLog), "", 100)
	if len(all) != 4 {
		t.Fatalf("want 4 ban/unban entries, got %d: %v", len(all), all)
	}
	first := all[0] // newest first
	if first["action"] != "ban" || first["jail"] != "sshd" || first["ip"] != "192.0.2.4" || first["timestamp"] != "2026-10-13 12:00:00,500" {
		t.Fatalf("newest entry: %v", first)
	}
	if all[2]["action"] != "unban" || all[2]["jail"] != "sshd" {
		t.Fatalf("unban entry: %v (the jail is the [name], not the [pid])", all[2])
	}
	if got := parseFail2BanHistory(strings.NewReader(sampleF2BLog), "recidive", 100); len(got) != 1 || got[0]["ip"] != "198.51.100.7" {
		t.Fatalf("jail filter: %v", got)
	}
	if got := parseFail2BanHistory(strings.NewReader(sampleF2BLog), "sshd", 2); len(got) != 2 || got[0]["ip"] != "192.0.2.4" {
		t.Fatalf("limit keeps the newest: %v", got)
	}
	var big strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&big, "2026-10-13 10:00:00,%03d fail2ban.actions [1]: NOTICE  [sshd] Ban 10.0.%d.%d\n", i%1000, i/250, i%250)
	}
	if got := parseFail2BanHistory(strings.NewReader(big.String()), "", 3); len(got) != 3 || got[0]["ip"] != "10.0.19.249" {
		t.Fatalf("large log: %d entries, newest %v", len(got), got)
	}
	if got := parseFail2BanHistory(strings.NewReader(""), "", 10); got == nil || len(got) != 0 {
		t.Fatalf("empty log must give an empty, non-nil list: %#v", got)
	}
}

func TestParseIgnoreIPList(t *testing.T) {
	cases := map[string][]string{
		fail2banIgnoreTree: {"127.0.0.0/8", "::1", "10.99.0.0/24"},
		"These IP addresses/networks are ignored:\n|- 192.0.2.0/24\n`- vpn.example.com\n": {"192.0.2.0/24", "vpn.example.com"},
		"No IP address/network is ignored\n":                                              {},
		"127.0.0.1/8 ::1 10.0.0.0/8\n":                                                    {"127.0.0.1/8", "::1", "10.0.0.0/8"},
	}
	for out, want := range cases {
		got := parseIgnoreIPList(out)
		if got == nil || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("parseIgnoreIPList(%q) = %#v, want %v", out, got, want)
		}
	}
}
