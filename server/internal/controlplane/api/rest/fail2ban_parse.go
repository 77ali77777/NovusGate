package rest

import (
	"net"
	"os"
	"regexp"
	"strings"
)

const fail2banLogPath = "/var/log/fail2ban.log"

// readFail2BanLog returns the fail2ban log the compose file mounts into the
// container (replaced in tests).
var readFail2BanLog = func() (string, error) {
	b, err := os.ReadFile(fail2banLogPath)
	return string(b), err
}

// f2bActionRe matches "<date> <time>,<ms> fail2ban.actions [pid]: NOTICE  [jail] (Restore )?(Ban|Unban) <ip>".
// The jail is the bracketed name directly before the action, not the [pid].
var f2bActionRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) .*\[([^\]]+)\]\s+(?:Restore )?(Ban|Unban)\s+(\S+)`)

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)

// fail2banLogAction classifies a fail2ban log line ("Unban" contains "Ban",
// so it must be checked first).
func fail2banLogAction(line string) string {
	switch {
	case strings.Contains(line, "Unban"):
		return "unban"
	case strings.Contains(line, "Ban"):
		return "ban"
	case strings.Contains(line, "Found"):
		return "found"
	}
	return ""
}

// parseFail2BanHistory returns the newest limit ban/unban entries, newest
// first, optionally only for one jail. It keeps at most limit entries in
// memory, whatever the log size.
func parseFail2BanHistory(log, jail string, limit int) []map[string]string {
	ring := []map[string]string{} // no preallocation: limit comes from the request
	for _, line := range strings.Split(log, "\n") {
		m := f2bActionRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || (jail != "" && m[2] != jail) {
			continue
		}
		entry := map[string]string{"raw": strings.TrimSpace(line), "timestamp": m[1], "jail": m[2],
			"action": strings.ToLower(m[3])}
		if net.ParseIP(m[4]) != nil {
			entry["ip"] = m[4]
		}
		if len(ring) == limit {
			ring = append(ring[1:], entry)
		} else {
			ring = append(ring, entry)
		}
	}
	out := make([]map[string]string, 0, len(ring))
	for i := len(ring) - 1; i >= 0; i-- {
		out = append(out, ring[i])
	}
	return out
}

// parseIgnoreIPList extracts the entries of `fail2ban-client get <jail>
// ignoreip`: the tree format ("|- 127.0.0.0/8", "`- ::1") and the legacy
// single-line list, skipping the header and the "nothing ignored" message.
func parseIgnoreIPList(out string) []string {
	entries := []string{}
	for _, tok := range strings.Fields(out) {
		if net.ParseIP(tok) != nil {
			entries = append(entries, tok)
			continue
		}
		if _, _, err := net.ParseCIDR(tok); err == nil {
			entries = append(entries, tok)
			continue
		}
		if hostnameRe.MatchString(tok) {
			entries = append(entries, tok)
		}
	}
	return entries
}
