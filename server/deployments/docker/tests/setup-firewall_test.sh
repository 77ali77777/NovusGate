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
    export SSHD_SBIN="${SSHD_SBIN:-/nonexistent/sshd}" # never the host's real sshd
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

# Case 4 (cont.): the invalid SSH_PORT still leaves 22 open and INPUT DROP last
log="$(run_case none "abc" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "SSH_PORT=abc"
assert_drop_last "$log" "SSH_PORT=abc"

# Case 4c: a non-numeric port in SSH_CONNECTION is ignored
log="$(run_case none "" "203.0.113.9 51000 198.51.100.4 ssh")"
if grep -q -- "--dport ssh" "$log"; then fail "a non-numeric SSH_CONNECTION port was used"; fi
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "SSH_CONNECTION ssh"
assert_drop_last "$log" "SSH_CONNECTION ssh"

# Case 4d: sshd outside PATH (non-login shells often lack /usr/sbin) is still asked;
# a failing sshd -T falls back to 22; repeated ports become one rule
sbin="$(mktemp -d)"
printf '#!/bin/bash
echo port 2244
echo port 2244
' > "$sbin/sshd"
chmod +x "$sbin/sshd"
log="$(SSHD_SBIN="$sbin/sshd" run_case none "" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 2244 -j ACCEPT" "sshd outside PATH"
[ "$(grep -c -x -F -- "-A INPUT -p tcp --dport 2244 -j ACCEPT" "$log")" = 1 ] || fail "a repeated sshd port must give one rule"
printf '#!/bin/bash
echo "error: bad config" >&2
exit 255
' > "$sbin/sshd"
log="$(SSHD_SBIN="$sbin/sshd" run_case none "" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "failing sshd -T"
assert_drop_last "$log" "failing sshd -T"

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

# --- P3b-2: engine-aware main ---
# run_main <FIREWALL_ENGINE or ""> <create ruleset: yes|no> <nft has table: yes|no>
# Prints the stub dir; calls.log has every host command in order.
run_main() {
  local engine="$1" ruleset="$2" has_table="$3" stub
  stub="$(mktemp -d)"
  mkdir -p "$stub/units" "$stub/jail.d"
  for cmd in iptables systemctl apt-get netfilter-persistent docker-compose sleep debconf-set-selections; do
    printf '#!/bin/bash\necho "%s $*" >> "%s/calls.log"\n' "$cmd" "$stub" > "$stub/$cmd"
    chmod +x "$stub/$cmd"
  done
  if [ "$has_table" = "yes" ]; then
    printf '#!/bin/bash\necho "nft $*" >> "%s/calls.log"\nexit 0\n' "$stub" > "$stub/nft"
  else
    printf '#!/bin/bash\necho "nft $*" >> "%s/calls.log"\n[ "$1" = "list" ] && exit 1\nexit 0\n' "$stub" > "$stub/nft"
  fi
  chmod +x "$stub/nft"
  printf '#!/bin/bash\necho "ii  iptables-persistent"\n' > "$stub/dpkg"
  chmod +x "$stub/dpkg"
  printf 'port 22\nport 2222\n' > "$stub/sshd.out"
  printf '#!/bin/bash\ncat "%s/sshd.out"\n' "$stub" > "$stub/sshd"
  chmod +x "$stub/sshd"
  if [ -n "$engine" ]; then printf 'POSTGRES_PASSWORD=x\nFIREWALL_ENGINE=%s\n' "$engine" > "$stub/.env"; fi
  if [ "$ruleset" = "yes" ]; then echo "table inet novusgate {}" > "$stub/firewall.nft"; fi
  (
    export PATH="$stub:/usr/bin:/bin"
    export ENV_FILE="$stub/.env" NFT_RULESET="$stub/firewall.nft" UNIT_DIR="$stub/units" F2B_JAIL_DIR="$stub/jail.d"
    unset SSH_PORT SSH_CONNECTION
    export SSHD_SBIN="${SSHD_SBIN:-/nonexistent/sshd}" # never the host's real sshd
    # shellcheck source=../setup-firewall.sh
    source "$SCRIPT"
    main > /dev/null
  )
  echo "$stub"
}

assert_has() { grep -q -F -- "$2" "$1" 2> /dev/null || fail "$3: missing '$2'"; }
assert_not() { if grep -q -F -- "$2" "$1" 2> /dev/null; then fail "$3: unexpected '$2'"; fi; }

# Case 6: default (no FIREWALL_ENGINE) = iptables mode; reverts a leftover nft engine after DROP
d="$(run_main "" yes yes)"
assert_has "$d/calls.log" "iptables -P INPUT DROP" "iptables mode"
assert_has "$d/calls.log" "nft delete table inet novusgate" "iptables mode reverts"
drop_at="$(grep -n -F "iptables -P INPUT DROP" "$d/calls.log" | cut -d: -f1)"
del_at="$(grep -n -F "nft delete table inet novusgate" "$d/calls.log" | cut -d: -f1)"
[ -n "$drop_at" ] && [ -n "$del_at" ] && [ "$drop_at" -lt "$del_at" ] || fail "iptables mode: the nft table must be removed only after INPUT DROP is back"
[ ! -f "$d/firewall.nft" ] || fail "iptables mode: the boot ruleset must be removed"
assert_has "$d/calls.log" "systemctl restart docker" "iptables mode"
assert_has "$d/jail.d/novusgate.local" "port = 22,2222" "fail2ban ports"
assert_not "$d/jail.d/novusgate.local" "banaction" "iptables mode fail2ban"

# Case 7: nft mode with a ruleset = control plane owns INPUT; iptables and Docker untouched
d="$(run_main nft yes yes)"
assert_not "$d/calls.log" "iptables " "nft mode"
assert_not "$d/calls.log" "systemctl restart docker" "nft mode"
assert_not "$d/calls.log" "nft delete table" "nft mode"
assert_has "$d/jail.d/novusgate.local" "banaction = nftables-multiport" "nft mode fail2ban"
assert_has "$d/jail.d/novusgate.local" "port = 22,2222" "nft mode fail2ban"

# Case 8: nft mode before the first apply = iptables baseline stays (control plane hands over later)
d="$(run_main nft no no)"
assert_has "$d/calls.log" "iptables -P INPUT DROP" "nft mode, no ruleset yet"
assert_not "$d/calls.log" "nft delete table" "nft mode, no ruleset yet"

# Case 9: boot unit and nftables in every mode; nftables.service is never enabled
for mode in "" nft; do
  d="$(run_main "$mode" yes yes)"
  unit="$d/units/novusgate-firewall.service"
  [ -f "$unit" ] || { fail "boot unit missing ($mode)"; continue; }
  assert_has "$unit" "ConditionPathExists=$d/firewall.nft" "boot unit"
  assert_has "$unit" "Before=network-pre.target docker.service" "boot unit"
  assert_has "$unit" "ExecStart=/usr/sbin/nft -f $d/firewall.nft" "boot unit"
  assert_has "$d/calls.log" "systemctl enable novusgate-firewall.service" "boot unit"
  assert_not "$d/calls.log" "enable nftables" "boot unit"
done

# Case 10: nft missing -> installed
d="$(mktemp -d)"
(
  export PATH="$d:/usr/bin:/bin"
  printf '#!/bin/bash\necho "apt-get $*" >> "%s/calls.log"\n' "$d" > "$d/apt-get"
  chmod +x "$d/apt-get"
  # shellcheck source=../setup-firewall.sh
  source "$SCRIPT"
  install_nftables > /dev/null
)
assert_has "$d/calls.log" "apt-get install -y nftables" "install_nftables"

# Case 11: default (iptables) mode must not fail when nftables cannot be
# installed (offline, dpkg lock); nft mode must stop instead.
# run_offline <FIREWALL_ENGINE> prints "rc=<exit>" and the stub dir.
run_offline() {
  local engine="$1" stub rc
  stub="$(mktemp -d)"
  mkdir -p "$stub/units" "$stub/jail.d"
  for cmd in iptables systemctl netfilter-persistent docker-compose sleep debconf-set-selections; do
    printf '#!/bin/bash\necho "%s $*" >> "%s/calls.log"\n' "$cmd" "$stub" > "$stub/$cmd"
    chmod +x "$stub/$cmd"
  done
  printf '#!/bin/bash\necho "apt-get $*" >> "%s/calls.log"\nexit 100\n' "$stub" > "$stub/apt-get"
  chmod +x "$stub/apt-get"
  printf '#!/bin/bash\necho "ii  iptables-persistent"\n' > "$stub/dpkg"
  chmod +x "$stub/dpkg"
  printf 'FIREWALL_ENGINE=%s\n' "$engine" > "$stub/.env"
  (
    export PATH="$stub:/usr/bin:/bin"
    export ENV_FILE="$stub/.env" NFT_RULESET="$stub/firewall.nft" UNIT_DIR="$stub/units" F2B_JAIL_DIR="$stub/jail.d"
    unset SSH_PORT SSH_CONNECTION
    export SSHD_SBIN="${SSHD_SBIN:-/nonexistent/sshd}" # never the host's real sshd
    # shellcheck source=../setup-firewall.sh
    source "$SCRIPT"
    main > /dev/null 2>&1
  )
  rc=$?
  echo "rc=$rc $stub"
}
out="$(run_offline iptables)"
d="${out#* }"
[ "${out%% *}" = "rc=0" ] || fail "iptables mode: an apt failure must not abort the script ($out)"
assert_has "$d/calls.log" "iptables -P INPUT DROP" "iptables mode, apt offline"
out="$(run_offline nft)"
[ "${out%% *}" != "rc=0" ] || fail "nft mode: a missing nftables must stop the script"

# Case 12: a trailing comment after FIREWALL_ENGINE does not change the mode
d="$(run_main "nft # switched in P3b" yes yes)"
assert_not "$d/calls.log" "iptables " "nft mode with a comment"

# Case 13: reverting stops an armed rollback timer before deleting the table,
# so the timer cannot load the nft snapshot back afterwards
d="$(run_main "" yes yes)"
stop_at="$(grep -n -F "systemctl stop novusgate-fw-rollback.timer" "$d/calls.log" | cut -d: -f1)"
del_at="$(grep -n -F "nft delete table inet novusgate" "$d/calls.log" | cut -d: -f1)"
[ -n "$stop_at" ] && [ -n "$del_at" ] && [ "$stop_at" -lt "$del_at" ] || fail "revert: the rollback timer must be stopped before the table is deleted"

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES failure(s)"
  exit 1
fi
echo "OK"
