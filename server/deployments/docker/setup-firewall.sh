#!/bin/bash
set -e

# setup-firewall.sh
# Configures iptables to secure NovusGate admin access via VPN

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
  } | grep -E '^[0-9]+$' | sort -un
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
  echo "[FIREWALL] Configuring iptables rules..."
  install_persistence
  apply_rules
  echo "[FIREWALL] Saving rules..."
  netfilter-persistent save
  restart_docker_stack
  echo "[FIREWALL] Done! Admin ports are now secured behind VPN."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
