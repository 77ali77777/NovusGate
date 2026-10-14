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
    apt-get install -y wireguard wireguard-tools curl
fi

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<'WGCONF'
{{CONFIG}}
WGCONF
chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "Checking in over the VPN..."
BODY=$(printf '{"node_info":{"os":"Linux","arch":"%s","hostname":"%s"}}' "$(uname -m)" "$(hostname)")
for i in $(seq 1 30); do
    if curl -fsS --max-time 5 -X POST "{{CHECKIN_URL}}" \
        -H "Content-Type: application/json" \
        -H "X-Enrollment-Token: {{TOKEN}}" \
        -d "$BODY" > /dev/null; then
        echo "Installation complete. This server is connected to the VPN."
        exit 0
    fi
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
