#!/bin/bash
# Tests for setup-firewall.sh. Run from anywhere: bash server/deployments/docker/tests/setup-firewall_test.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../setup-firewall.sh"
FAILURES=0

fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

if ! grep -q '^apply_rules()' "$SCRIPT"; then
  echo "FAIL: setup-firewall.sh has no apply_rules function"
  exit 1
fi

# run_case <sshd -T output or "none"> <SSH_PORT> <SSH_CONNECTION>
# Prints the path of a log with one line per iptables call.
run_case() {
  local sshd_out="$1" ssh_port="$2" ssh_conn="$3"
  local stub
  stub="$(mktemp -d)"
  printf '#!/bin/bash\necho "$*" >> "%s/iptables.log"\n' "$stub" > "$stub/iptables"
  chmod +x "$stub/iptables"
  if [ "$sshd_out" != "none" ]; then
    printf '%s\n' "$sshd_out" > "$stub/sshd.out"
    printf '#!/bin/bash\ncat "%s/sshd.out"\n' "$stub" > "$stub/sshd"
    chmod +x "$stub/sshd"
  fi
  (
    export PATH="$stub:/usr/bin:/bin"
    unset SSH_PORT SSH_CONNECTION
    if [ -n "$ssh_port" ]; then export SSH_PORT="$ssh_port"; fi
    if [ -n "$ssh_conn" ]; then export SSH_CONNECTION="$ssh_conn"; fi
    # shellcheck source=../setup-firewall.sh
    source "$SCRIPT"
    apply_rules > /dev/null
  )
  echo "$stub/iptables.log"
}

line_of() { grep -n -x -F -- "$2" "$1" | head -n1 | cut -d: -f1; }

assert_rule() {
  if [ -z "$(line_of "$1" "$2")" ]; then fail "$3: missing '$2'"; fi
}

assert_drop_last() {
  local log="$1" name="$2"
  local first last drop
  first="$(head -n1 "$log")"
  last="$(tail -n1 "$log")"
  [ "$first" = "-P INPUT ACCEPT" ] || fail "$name: first call is '$first', want '-P INPUT ACCEPT'"
  [ "$last" = "-P INPUT DROP" ] || fail "$name: last call is '$last', want '-P INPUT DROP'"
  drop="$(line_of "$log" "-P INPUT DROP")"
  [ "$drop" = "$(wc -l < "$log" | tr -d ' ')" ] || fail "$name: INPUT DROP is not the final call"
}

# Case 1: sshd listens on 2222 and 22
log="$(run_case $'port 2222\nport 22' "" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 2222 -j ACCEPT" "sshd ports"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "sshd ports"
assert_drop_last "$log" "sshd ports"

# Case 2: no sshd binary, port taken from the current SSH session
log="$(run_case none "" "203.0.113.9 51000 198.51.100.4 2200")"
assert_rule "$log" "-A INPUT -p tcp --dport 2200 -j ACCEPT" "SSH_CONNECTION"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "SSH_CONNECTION"

# Case 3: nothing detected -> 22 only, still safe ordering
log="$(run_case none "" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "fallback"
assert_drop_last "$log" "fallback"

# Case 4: invalid SSH_PORT is ignored, valid one is used
log="$(run_case none "abc" "")"
if grep -q -- "--dport abc" "$log"; then fail "invalid SSH_PORT was used"; fi
log="$(run_case none "2022" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 2022 -j ACCEPT" "SSH_PORT"

# Case 4b: out-of-range ports are ignored; 22 stays open and INPUT DROP is still last
for bad in 0 70000; do
  log="$(run_case none "$bad" "")"
  if grep -q -- "--dport $bad " "$log"; then fail "out-of-range SSH_PORT $bad was used"; fi
  assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "SSH_PORT=$bad"
  assert_drop_last "$log" "SSH_PORT=$bad"
done
log="$(run_case none "" "203.0.113.9 51000 198.51.100.4 99999")"
if grep -q -- "--dport 99999 " "$log"; then fail "out-of-range SSH_CONNECTION port was used"; fi
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "SSH_CONNECTION 99999"
assert_drop_last "$log" "SSH_CONNECTION 99999"

# Case 5: every original NovusGate rule is still present
log="$(run_case none "" "")"
for rule in \
  "-A INPUT -i lo -j ACCEPT" \
  "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" \
  "-A INPUT -p udp --dport 51820:51900 -j ACCEPT" \
  "-A INPUT -i wg0 -p tcp --dport 3007 -j ACCEPT" \
  "-A INPUT -i wg+ -p tcp --dport 8080 -j ACCEPT" \
  "-A INPUT -i wg+ -p tcp --dport 8443 -j ACCEPT" \
  "-A INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT" \
  "-A INPUT -p tcp --dport 3007 -j DROP" \
  "-A INPUT -p tcp --dport 5432 -j DROP" \
  "-A INPUT -p icmp -j ACCEPT" \
  "-P FORWARD ACCEPT" \
  "-P OUTPUT ACCEPT" \
  "-F" \
  "-X"; do
  assert_rule "$log" "$rule" "original rules"
done

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES failure(s)"
  exit 1
fi
echo "OK"
