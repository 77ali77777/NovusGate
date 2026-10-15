
#!/bin/bash
set -e
@@SHELL_HELPERS@@
INSTALL_DIR="/opt/NovusGate"
ENV_FILE="$INSTALL_DIR/server/deployments/docker/.env"

# novusgate_ifaces WGDIR DB_IFACES prints the WireGuard interfaces NovusGate
# created: wg0, the networks in its database and configs carrying the PostUp
# line the control plane writes. Other WireGuard tunnels are left alone.
novusgate_ifaces() {
  local dir="$1" list="wg0 $2" f
  for f in "$dir"/wg*.conf; do
    [ -f "$f" ] || continue
    if grep -q 'ip route get 8.8.8.8' "$f"; then
      list="$list $(basename "$f" .conf)"
    fi
  done
  echo $list | tr ' ' '\n' | grep -E '^wg[0-9]+$' | sort -u -V
}

echo "=========================================="
echo "  NovusGate UNINSTALL"
echo "  WARNING: This deletes NovusGate and ALL its data."
echo "  Other containers, images, volumes and firewall rules stay."
echo "=========================================="

echo "[1/6] Reading NovusGate networks..."
DB_IFACES=""
if [ -f "$ENV_FILE" ] && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx novusgate-postgres; then
  DB_USER_V=$(grep -E '^DB_USER=' "$ENV_FILE" | tail -n1 | cut -d= -f2-)
  DB_NAME_V=$(grep -E '^DB_NAME=' "$ENV_FILE" | tail -n1 | cut -d= -f2-)
  DB_IFACES=$(docker exec novusgate-postgres psql -U "${DB_USER_V:-novusgate}" -d "${DB_NAME_V:-novusgate}" -Atc "SELECT interface_name FROM networks" 2>/dev/null | tr '\n' ' ' || true)
fi

echo "[2/6] Stopping NovusGate containers..."
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  cd "$INSTALL_DIR"
  # --rmi local: only the images NovusGate built (control-plane, web)
  compose -f server/deployments/docker/docker-compose.yml down -v --rmi local --remove-orphans 2>/dev/null || true
  cd /
fi
docker ps -a --format "{{.ID}} {{.Names}}" | grep -i novusgate | awk '{print $1}' | xargs -r docker rm -f || true

echo "[3/6] Removing NovusGate WireGuard interfaces..."
for IFACE in $(novusgate_ifaces /etc/wireguard "$DB_IFACES"); do
  echo "  - $IFACE"
  systemctl stop "wg-quick@$IFACE" 2>/dev/null || true
  systemctl disable "wg-quick@$IFACE" 2>/dev/null || true
  ip link delete "$IFACE" 2>/dev/null || true
  rm -f "/etc/wireguard/$IFACE.conf"
done

echo "[4/6] Removing NovusGate firewall rules..."
systemctl stop novusgate-fw-rollback.timer novusgate-fw-rollback.service 2>/dev/null || true
systemctl disable novusgate-firewall.service 2>/dev/null || true
rm -f /etc/systemd/system/novusgate-firewall.service
systemctl daemon-reload 2>/dev/null || true
if command -v nft &> /dev/null; then
  nft delete table inet novusgate 2>/dev/null || true
fi
# setup-firewall.sh replaced INPUT: open it again. Docker's chains (FORWARD,
# nat) are left alone, so other containers keep working.
iptables -P INPUT ACCEPT
iptables -F INPUT
iptables -t mangle -D PREROUTING -p tcp -m multiport --dports 3007,5432,8080,8443 -j NOVUSGATE-ADMIN 2>/dev/null || true
iptables -t mangle -F NOVUSGATE-ADMIN 2>/dev/null || true
iptables -t mangle -X NOVUSGATE-ADMIN 2>/dev/null || true
if command -v ip6tables &> /dev/null; then
    ip6tables -t mangle -D PREROUTING -p tcp -m multiport --dports 3007,5432,8080,8443 -j NOVUSGATE-ADMIN 2>/dev/null || true
    ip6tables -t mangle -F NOVUSGATE-ADMIN 2>/dev/null || true
    ip6tables -t mangle -X NOVUSGATE-ADMIN 2>/dev/null || true
fi
if [ -f /etc/fail2ban/jail.d/novusgate.local ]; then
  rm -f /etc/fail2ban/jail.d/novusgate.local
  systemctl reload fail2ban 2>/dev/null || true
fi
# setup-firewall.sh moved fail2ban's log to /var/log/novusgate; put it back
rm -f /etc/fail2ban/fail2ban.d/novusgate.local
rm -f /etc/logrotate.d/novusgate-fail2ban
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  fail2ban-client set logtarget /var/log/fail2ban.log > /dev/null 2>&1 || true
fi
rm -rf /var/log/novusgate
# an earlier setup-firewall.sh added a marker line and copytruncate to fail2ban's logrotate
[ -f /etc/logrotate.d/fail2ban ] && sed -i '/# NovusGate: keep the inode/{N;d}' /etc/logrotate.d/fail2ban || true
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
fi

echo "[5/6] Removing files..."
rm -rf "$INSTALL_DIR"
rm -rf /etc/novusgate /var/lib/novusgate

echo "[6/6] Done."
echo "[DONE] NovusGate removed. The server is ready for a fresh install."
