
#!/bin/bash
set -e
@@SHELL_HELPERS@@

INSTALL_DIR="/opt/NovusGate"
@@REINSTALL_DB_GUARD@@
echo "=========================================="
echo "  NovusGate REINSTALL"
echo "=========================================="

# Backup .env before deleting
if [ -f "$INSTALL_DIR/server/deployments/docker/.env" ]; then
  echo "Preserving old config..."
  cp -p "$INSTALL_DIR/server/deployments/docker/.env" /tmp/NovusGate.env.bak # keeps its 600 mode
  if [ -f "$INSTALL_DIR/web/.env" ]; then
    cp "$INSTALL_DIR/web/.env" /tmp/NovusGate.web.env.bak
  fi
fi

# Stop and remove existing
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  cd "$INSTALL_DIR"
  # NO -v flag here, keep volumes!
  compose -f server/deployments/docker/docker-compose.yml down --rmi local 2>/dev/null || true
fi

# Remove files but KEEP the database (server/data) and admin-vpn.conf
@@CLEAN_INSTALL_DIR_FN@@
echo "Cleaning files (preserving server/data and admin-vpn.conf)..."
clean_install_dir "$INSTALL_DIR"

# Extract new
mkdir -p "$INSTALL_DIR"
tar -xzf /tmp/NovusGate.tar.gz -C "$INSTALL_DIR"
rm -f /tmp/NovusGate.tar.gz

# Note: In reinstall, we might want to keep old secrets or generate new ones?
# Usually reinstall means "nuclear option", so let's check if .env exists, if so keep it, else generate
cd "$INSTALL_DIR"

# Restore or generate .env
if [ -f "/tmp/NovusGate.env.bak" ]; then
  echo "Restoring configuration..."
  # Creating directory structure if missing after clean
  mkdir -p server/deployments/docker
  mv /tmp/NovusGate.env.bak server/deployments/docker/.env
  if [ -f /tmp/NovusGate.web.env.bak ]; then
    mkdir -p web
    mv /tmp/NovusGate.web.env.bak web/.env
  fi

  # Ensure WG_SERVER_ENDPOINT exists
  if ! grep -q "WG_SERVER_ENDPOINT" server/deployments/docker/.env; then
    SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
    echo "WG_SERVER_ENDPOINT=$SERVER_IP" >> server/deployments/docker/.env
  fi

  # Ensure MASTER_KEY exists (seals node private keys; added in P4c)
@@ENSURE_MASTER_KEY@@
else
  echo "Generating new keys (Config provided)..."
  generate_secret() { openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -t x1 | tr -d ' \n'; }
  
  API_KEY=$(generate_secret)
  JWT_SECRET=$(generate_secret)
  MASTER_KEY=@@MASTER_KEY_GEN@@

  # Use provided or generate
  DB_NAME=@@DB_NAME@@
  DB_USER=@@DB_USER@@
  ADMIN_USERNAME=@@ADMIN_USERNAME@@
  ADMIN_CIDR=@@ADMIN_CIDR@@
  DB_PASSWORD=@@DB_PASSWORD@@
  if [ -z "$DB_PASSWORD" ]; then
     DB_PASSWORD=$(generate_secret)
  fi

  ADMIN_PASSWORD=@@ADMIN_PASSWORD@@
  if [ -z "$ADMIN_PASSWORD" ]; then
     ADMIN_PASSWORD=$(generate_secret)
  fi
  
  SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
  
  mkdir -p server/deployments/docker
  cat <<EOF > server/deployments/docker/.env
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$JWT_SECRET

API_KEY=$API_KEY
MASTER_KEY=$MASTER_KEY
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD
WG_SERVER_ENDPOINT=$SERVER_IP
ADMIN_CIDR=$ADMIN_CIDR
EOF
  # No web/.env: since P4b the panel calls the API through its own nginx,
  # which adds the API key; the key is never copied into the web build.
fi
# DB password, API key and master key: root only, as install.sh writes it.
chmod 600 server/deployments/docker/.env

# sshd_source sets SSHD_SOURCE for the sshd jail: auth.log where syslog
# writes one, else the journal (Debian 12 has no rsyslog by default).
sshd_source() {
  if [ -f "${AUTH_LOG:-/var/log/auth.log}" ]; then
    SSHD_SOURCE="logpath = ${AUTH_LOG:-/var/log/auth.log}"
  else
    apt_get install -y python3-systemd
    SSHD_SOURCE="backend = systemd"
  fi
}

# Ensure Fail2Ban is installed
if ! command -v fail2ban-client &> /dev/null; then
  echo "Installing Fail2Ban..."
  apt_get update -qq
  apt_get install -y fail2ban
  
  # Create SSH jail config
  sshd_source
  cat <<F2B > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
$SSHD_SOURCE
maxretry = 3
bantime = 3600
F2B

  systemctl enable fail2ban
  systemctl restart fail2ban
  echo "Fail2Ban installed ✓"
fi

# Setup Firewall (re-run to ensure rules match new config if relevant, though mostly static)
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  # Fix Windows CRLF line endings
  sed -i 's/\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  chmod +x "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
fi

# Start
echo "Starting services..."
compose -f server/deployments/docker/docker-compose.yml up -d --build

echo "Waiting for DB..."
sleep 20

# Init with dynamic params
echo "Re-Initializing NovusGate Control Plane..."
# Init command skipped (Admin Network auto-bootstrapped)

echo "REINSTALL COMPLETE!"
docker ps | grep -i novusgate || true
