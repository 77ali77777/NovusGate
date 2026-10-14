#!/bin/bash
set -e

# setup-firewall.sh
# Configures iptables to secure NovusGate admin access via VPN

ENV_FILE="${ENV_FILE:-/opt/NovusGate/server/deployments/docker/.env}"
NFT_RULESET="${NFT_RULESET:-/etc/novusgate/firewall.nft}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
F2B_JAIL_DIR="${F2B_JAIL_DIR:-/etc/fail2ban/jail.d}"
BOOT_UNIT=novusgate-firewall.service

# detect_ssh_ports prints every TCP port SSH must stay reachable on, one per line.
# Sources: port 22 (always, as before), SSH_PORT env, the port of the current
# SSH session (SSH_CONNECTION) and the ports reported by `sshd -T`.
detect_ssh_ports() {
  {
    echo 22
    if [ -n "${SSH_PORT:-}" ]; then echo "$SSH_PORT"; fi
    if [ -n "${SSH_CONNECTION:-}" ]; then echo "${SSH_CONNECTION##* }"; fi
    if command -v sshd > /dev/null 2>&1; then
      sshd -T 2> /dev/null | awk '$1 == "port" {print $2}'
    fi
  } | grep -E '^[0-9]+$' | awk '$1 >= 1 && $1 <= 65535' | sort -un
}

# firewall_engine prints FIREWALL_ENGINE from the compose .env (iptables when unset).
firewall_engine() {
  local v=""
  if [ -f "$ENV_FILE" ]; then
    # cut -d'#' drops a trailing "# comment" (engine names never contain #).
    v="$(grep -E '^FIREWALL_ENGINE=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | cut -d'#' -f1 | tr -d "\"' \t\r" | tr '[:upper:]' '[:lower:]')"
  fi
  echo "${v:-iptables}"
}

# install_nftables installs the nft CLI the boot unit and the control plane's
# host-side rollback need. nftables.service is never enabled: its default
# config flushes the whole ruleset, including Docker's.
install_nftables() {
  if ! command -v nft > /dev/null 2>&1; then
    echo "[FIREWALL] Installing nftables..."
    apt-get update -qq
    apt-get install -y nftables
  fi
}

# install_boot_unit loads the control plane's ruleset before Docker on every
# boot; without the ruleset file (iptables mode) it does nothing.
install_boot_unit() {
  cat > "$UNIT_DIR/$BOOT_UNIT" <<UNIT
[Unit]
Description=NovusGate nftables firewall (table inet novusgate)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target docker.service
After=local-fs.target
ConditionPathExists=$NFT_RULESET

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $NFT_RULESET

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$BOOT_UNIT"
}

# configure_fail2ban makes the sshd jail cover every SSH port and, in nft
# mode, ban through nftables instead of iptables.
configure_fail2ban() {
  local engine="$1" ports
  [ -d "$F2B_JAIL_DIR" ] || return 0
  ports="$(detect_ssh_ports | paste -sd, -)"
  {
    echo "# Managed by NovusGate setup-firewall.sh"
    echo "[sshd]"
    echo "port = $ports"
    if [ "$engine" = "nft" ]; then
      echo "banaction = nftables-multiport"
      echo "banaction_allports = nftables-allports"
    fi
  } > "$F2B_JAIL_DIR/novusgate.local"
  if systemctl is-active --quiet fail2ban 2> /dev/null; then
    systemctl reload fail2ban || echo "[FIREWALL] Warning: fail2ban reload failed; check 'fail2ban-client status'"
  fi
}

# remove_nft_engine undoes FIREWALL_ENGINE=nft; call it only after the
# iptables baseline (INPUT DROP) is back.
remove_nft_engine() {
  # An armed rollback timer would load the nft snapshot back after the
  # table is gone; stop it first (it is not loaded when nothing is pending).
  systemctl stop novusgate-fw-rollback.timer > /dev/null 2>&1 || true
  if nft list table inet novusgate > /dev/null 2>&1; then
    echo "[FIREWALL] Removing table inet novusgate (FIREWALL_ENGINE is not nft)..."
    nft delete table inet novusgate
  fi
  rm -f "$NFT_RULESET"
}

install_persistence() {
  # Install iptables-persistent if not present
  if ! dpkg -l | grep -q iptables-persistent; then
    echo "[FIREWALL] Installing iptables-persistent..."
    # Non-interactive installation
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get update -qq && apt-get install -y iptables-persistent
  fi
}

apply_rules() {
  echo "[FIREWALL] Applying rules..."

  # 1. Accept while the chain is rebuilt, so a failure part-way through can
  #    never leave INPUT=DROP without the SSH rule (lockout).
  iptables -P INPUT ACCEPT
  iptables -F
  iptables -X

  # 2. Default Policies (INPUT switches to DROP at the very end)
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  # 3. Allow Loopback
  iptables -A INPUT -i lo -j ACCEPT

  # 4. Allow Established/Related
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # 5. Allow SSH (Critical) on every port sshd uses
  local port
  for port in $(detect_ssh_ports); do
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done

  # 6. Allow WireGuard Range
  iptables -A INPUT -p udp --dport 51820:51900 -j ACCEPT  # wg0-wg80 (NovusGate Range)

  # 7. Allow Admin Services ONLY from wg0 (Admin Network)
  iptables -A INPUT -i wg0 -p tcp --dport 3007 -j ACCEPT   # Web Dashboard

  # 8. Allow All VPN Networks (wg+) to access API/gRPC
  # Nodes in any network need to talk to the control plane
  iptables -A INPUT -i wg+ -p tcp --dport 8080 -j ACCEPT   # API
  iptables -A INPUT -i wg+ -p tcp --dport 8443 -j ACCEPT   # gRPC

  # 9. Optional: Allow Database access only from Admin (wg0)
  iptables -A INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT

  # 10. Explicitly DROP public access to Admin Services (Safety Net)
  iptables -A INPUT -p tcp --dport 3007 -j DROP
  iptables -A INPUT -p tcp --dport 5432 -j DROP
  # Note: 8080 and 8443 are allowed via wg+, but should be dropped from public/eth0 if not intended.
  # For now, we rely on Default DROP policy for public interfaces.

  # 11. Allow ICMP (Ping)
  iptables -A INPUT -p icmp -j ACCEPT

  # 12. Default DROP only after every allow rule is in place
  iptables -P INPUT DROP
}

restart_docker_stack() {
  # Restart Docker to recreate DOCKER chain
  echo "[FIREWALL] Restarting Docker to restore networking..."
  systemctl restart docker

  # Wait for Docker to be ready
  sleep 5

  # Restart NovusGate containers (only if .env exists)
  echo "[FIREWALL] Restarting NovusGate containers..."
  if [ -f "/opt/NovusGate/server/deployments/docker/.env" ]; then
    cd /opt/NovusGate
    docker-compose -f server/deployments/docker/docker-compose.yml up -d
  else
    echo "[FIREWALL] Warning: .env not found, skipping container restart"
    echo "[FIREWALL] Containers will be started by the installer script"
  fi
}

main() {
  local engine
  engine="$(firewall_engine)"
  echo "[FIREWALL] Engine: $engine"
  if [ "$engine" = "nft" ]; then
    install_nftables
    install_boot_unit
  else
    # iptables mode does not need them yet; a failed install (offline, dpkg
    # lock) must not stop the iptables baseline below.
    install_nftables || echo "[FIREWALL] Warning: nftables could not be installed; FIREWALL_ENGINE=nft will refuse to start until it is"
    install_boot_unit || echo "[FIREWALL] Warning: $BOOT_UNIT could not be installed; FIREWALL_ENGINE=nft will refuse to start until it is"
  fi
  configure_fail2ban "$engine"
  if [ "$engine" = "nft" ] && [ -f "$NFT_RULESET" ]; then
    echo "[FIREWALL] FIREWALL_ENGINE=nft: the control plane owns INPUT filtering; iptables and Docker are left unchanged."
    return 0
  fi
  echo "[FIREWALL] Configuring iptables rules..."
  install_persistence
  apply_rules
  if [ "$engine" != "nft" ]; then
    remove_nft_engine
  fi
  echo "[FIREWALL] Saving rules..."
  netfilter-persistent save
  restart_docker_stack
  echo "[FIREWALL] Done! Admin ports are now secured behind VPN."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
