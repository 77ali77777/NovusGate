package rest

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

// enrollmentTTL is how long an install script's token can check in.
const enrollmentTTL = 15 * time.Minute

// enrollmentHeader carries the one-time token of an install script.
const enrollmentHeader = "X-Enrollment-Token"

var checkinPathRe = regexp.MustCompile(`^/api/v1/nodes/[^/]+/checkin$`)

// isEnrollmentCheckin reports whether r is a node checking in with an
// enrollment token. The auth middlewares let only this request shape
// through; handleNodeCheckIn then validates the token.
func isEnrollmentCheckin(r *http.Request) bool {
	return r.Method == http.MethodPost && checkinPathRe.MatchString(r.URL.Path) && r.Header.Get(enrollmentHeader) != ""
}

// installScript returns the shell script that installs WireGuard with
// config, brings the tunnel up and then checks in over it.
func installScript(config, checkinURL, token string) string {
	return strings.NewReplacer(
		"{{CONFIG}}", config,
		"{{CHECKIN_URL}}", checkinURL,
		"{{TOKEN}}", token,
	).Replace(installScriptTemplate)
}

// The config heredoc is quoted so nothing in it expands. The checkin runs
// after the tunnel is up because the API is reachable only over the VPN.
const installScriptTemplate = `#!/bin/bash
# NovusGate node installer. The enrollment token in it works once, for 15
# minutes. Run as root on the new server.
set -euo pipefail
umask 077 # wg0.conf holds the private key: never readable by others

echo "Installing WireGuard..."
if ! command -v wg > /dev/null 2>&1; then
    apt-get update
    apt-get install -y wireguard wireguard-tools
fi
if ! command -v curl > /dev/null 2>&1; then
    apt-get update
    apt-get install -y curl
fi

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<'WGCONF'
{{CONFIG}}
WGCONF
chmod 600 /etc/wireguard/wg0.conf

# wg-quick applies a DNS line through resolvconf, which Ubuntu does not ship;
# resolvectl (systemd-resolved) speaks it when called by that name.
if grep -q '^DNS *=' /etc/wireguard/wg0.conf && ! command -v resolvconf > /dev/null 2>&1; then
    if command -v resolvectl > /dev/null 2>&1; then
        ln -sf "$(command -v resolvectl)" /usr/local/sbin/resolvconf
    else
        apt-get update
        apt-get install -y openresolv
    fi
fi

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "Checking in over the VPN..."
# The token goes to curl through a private file, so it never shows in ps.
HDR=$(mktemp)
trap 'rm -f "$HDR"' EXIT
printf 'X-Enrollment-Token: %s\n' '{{TOKEN}}' > "$HDR"
# Only safe characters reach the JSON body.
ARCH=$(uname -m | tr -cd 'A-Za-z0-9._-')
HOST=$(hostname | tr -cd 'A-Za-z0-9._-')
BODY=$(printf '{"node_info":{"os":"Linux","arch":"%s","hostname":"%s"}}' "$ARCH" "$HOST")
for i in $(seq 1 30); do
    CODE=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X POST "{{CHECKIN_URL}}" \
        -H "Content-Type: application/json" -H @"$HDR" -d "$BODY" || true)
    case "$CODE" in
    200)
        echo "Installation complete. This server is connected to the VPN."
        exit 0
        ;;
    401)
        echo "The enrollment token was already used or has expired. If an earlier attempt timed out, the check-in may already have succeeded: check the node in the panel; otherwise generate a new install script." >&2
        exit 1
        ;;
    esac
    sleep 2
done
echo "WireGuard is up, but the check-in failed. Check the tunnel with: wg show" >&2
exit 1
`

// withoutWireguardLabels drops label keys starting with "wireguard_": keys
// and WireGuard settings are never set through labels.
func withoutWireguardLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if !strings.HasPrefix(k, "wireguard_") {
			out[k] = v
		}
	}
	return out
}

// checkinBodyLimit caps a checkin body: it may come from a caller without a
// session, and a node's report is a few hundred bytes.
const checkinBodyLimit = 64 << 10
