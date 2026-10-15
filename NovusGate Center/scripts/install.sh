
#!/bin/bash
set -e
@@SHELL_HELPERS@@

INSTALL_DIR="/opt/NovusGate"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
@@ALREADY_INSTALLED_GUARD@@@@PREFLIGHT_FN@@
preflight || {
  rm -f /tmp/NovusGate.tar.gz
  exit @@EXIT_PREFLIGHT@@
}

# Configuration Variables
ADMIN_USERNAME=@@ADMIN_USERNAME@@
ADMIN_PASSWORD=@@ADMIN_PASSWORD@@ # Empty means auto-generate
VPN_IP=@@VPN_IP@@
VPN_SUBNET=@@VPN_SUBNET@@
VPN_CLIENT_IP=@@VPN_CLIENT_IP@@

# Database Config
DB_NAME=@@DB_NAME@@
DB_USER=@@DB_USER@@
DB_PASSWORD=@@DB_PASSWORD@@ # Empty means auto-generate

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "=========================================="
echo "  NovusGate Server Installer"
echo "=========================================="

# Update system
log_info "Updating system..."
apt_get update -qq

# Install Docker if not present
if ! command -v docker &> /dev/null; then
  log_info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
else
  log_info "Docker already installed ✓"
fi

# Docker Compose: v2 plugin (get.docker.com installs it); v1 only as a fallback
if docker compose version &> /dev/null || command -v docker-compose &> /dev/null; then
  log_info "Docker Compose already installed ✓"
else
  log_info "Installing Docker Compose..."
  apt_get install -y docker-compose-plugin || apt_get install -y docker-compose-v2 || apt_get install -y docker-compose
fi

# Extract archive
log_info "Extracting archive..."
mkdir -p "$INSTALL_DIR"
tar -xzf /tmp/NovusGate.tar.gz -C "$INSTALL_DIR"
rm -f /tmp/NovusGate.tar.gz

# Generate secrets
log_info "Generating security keys..."
generate_secret() {
  openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -t x1 | tr -d ' 
'
}

API_KEY=$(generate_secret)
JWT_SECRET=$(generate_secret)
# Seals node private keys in the database (64 hex characters).
MASTER_KEY=@@MASTER_KEY_GEN@@

if [ -z "$DB_PASSWORD" ]; then
  DB_PASSWORD=$(generate_secret)
fi

if [ -z "$ADMIN_PASSWORD" ]; then
  ADMIN_PASSWORD=$(generate_secret)
fi

# Detect Server Public IP
log_info "Detecting Server IP..."
SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
log_info "Server IP: $SERVER_IP"


# ==========================================
# ADMIN VPN SETUP (MOVED BEFORE DOCKER START)
# ==========================================
log_info "Configuring Admin VPN Security Layer..."

# Pre-flight Cleanup (Prevent existing wg0 conflicts)
log_info "Cleaning up previous VPN state..."
# Pre-flight Cleanup (Prevent existing wg0 conflicts)
log_info "Cleaning up previous VPN state..."

# 1. Stop existing Docker containers holding ports
if command -v docker &> /dev/null; then
  docker ps -a --format "{{.ID}} {{.Names}}" | grep -i novusgate | awk '{print $1}' | xargs -r docker stop || true
  docker ps -a --format "{{.ID}} {{.Names}}" | grep -i novusgate | awk '{print $1}' | xargs -r docker rm || true
fi

# 2. Stop Systemd Services
systemctl stop wg-quick@wg0 2>/dev/null || true
systemctl disable wg-quick@wg0 2>/dev/null || true

# 3. Force remove interface if it exists (e.g. from stuck container)
ip link delete wg0 2>/dev/null || true

# 4. Clean Configs
rm -f /etc/wireguard/wg0.conf
rm -f /etc/wireguard/wg1.conf # Clean old wg1 if exists

# Install WireGuard
if ! command -v wg &> /dev/null; then
  log_info "Installing WireGuard..."
  apt_get install -y wireguard
fi

# Install Fail2Ban for SSH protection
if ! command -v fail2ban-client &> /dev/null; then
  log_info "Installing Fail2Ban..."
  apt_get install -y fail2ban
  
  # Create SSH jail config
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
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
F2B

  # Enable and start fail2ban
  systemctl enable fail2ban
  systemctl restart fail2ban
  log_info "Fail2Ban installed and configured ✓"
else
  log_info "Fail2Ban already installed ✓"
fi

# Generate Keys
umask 077
WG_SERVER_PRIVATE_KEY=$(wg genkey)
WG_SERVER_PUBLIC_KEY=$(echo "$WG_SERVER_PRIVATE_KEY" | wg pubkey)
WG_CLIENT_PRIVATE_KEY=$(wg genkey)
WG_CLIENT_PUBLIC_KEY=$(echo "$WG_CLIENT_PRIVATE_KEY" | wg pubkey)

# Create Server Config (wg0)
mkdir -p /etc/wireguard
cat <<WG0 > /etc/wireguard/wg0.conf
[Interface]
Address = $VPN_IP/24
ListenPort = 51820
PrivateKey = $WG_SERVER_PRIVATE_KEY
SaveConfig = false

[Peer]
PublicKey = $WG_CLIENT_PUBLIC_KEY
AllowedIPs = $VPN_CLIENT_IP/32
WG0

# Enable and Start wg0
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

# Generate Client Config
cat <<CLIENT > /tmp/admin-vpn.conf
[Interface]
PrivateKey = $WG_CLIENT_PRIVATE_KEY
Address = $VPN_CLIENT_IP/32
DNS = 8.8.8.8

[Peer]
PublicKey = $WG_SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = $VPN_SUBNET
PersistentKeepalive = 25
CLIENT

# Also save to permanent location
cp /tmp/admin-vpn.conf $INSTALL_DIR/admin-vpn.conf

log_info "Admin VPN configured."

# Apply Firewall (MOVED BEFORE DOCKER START)
# This includes 'systemctl restart docker' which fixes the chain issues
log_info "Applying Firewall Rules..."
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  if command -v sed &> /dev/null; then
    sed -i 's/\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  fi
  chmod +x "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
elif [ -f "$INSTALL_DIR/deployments/docker/setup-firewall.sh" ]; then
  chmod +x "$INSTALL_DIR/deployments/docker/setup-firewall.sh"
  "$INSTALL_DIR/deployments/docker/setup-firewall.sh"
else
  log_warn "setup-firewall.sh not found. Skipping firewall step."
fi


# Create Server .env
# Ensure directory exists
mkdir -p "$INSTALL_DIR/server/deployments/docker"

cat <<EOF > "$INSTALL_DIR/server/deployments/docker/.env"
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$JWT_SECRET

API_KEY=$API_KEY
MASTER_KEY=$MASTER_KEY
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD
WG_SERVER_ENDPOINT=$SERVER_IP
ADMIN_CIDR=$VPN_SUBNET
EOF
chmod 600 "$INSTALL_DIR/server/deployments/docker/.env"
# No web/.env: since P4b the panel calls the API through its own nginx,
# which adds the API key; the key is never copied into the web build.


# Start services
log_info "Starting services..."
cd "$INSTALL_DIR"
compose -f server/deployments/docker/docker-compose.yml up -d --build

# Wait
log_info "Waiting 30 seconds..."
sleep 30

# Initialize
log_info "Skipping default network creation (Admin Network is auto-created)..."
# We DO NOT run init anymore, because we only want the Admin Network initially.
# INIT_OUTPUT=$(compose -f server/deployments/docker/docker-compose.yml exec -T control-plane ./novusgate-server init --name "$NETWORK_NAME" --cidr "$NETWORK_CIDR" 2>&1 || true)
# echo "$INIT_OUTPUT"

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=========================================="
echo -e "${GREEN}  INSTALLATION COMPLETE!${NC}"
echo "=========================================="
echo "Server IP: $SERVER_IP"
echo ""
echo "------------------------------------------"
echo "  🔒 ADMIN VPN CONFIG (REQUIRED)  "
echo "------------------------------------------"
echo "The Admin Dashboard is now HIDDEN behind this VPN."
echo "You MUST connect to this VPN to access the dashboard."
echo ""
echo "BEGIN_VPN_CONFIG"
cat /tmp/admin-vpn.conf
echo "END_VPN_CONFIG"
echo ""
echo "Save this as 'admin-vpn.conf' and import into WireGuard."
echo "------------------------------------------"
echo ""
echo "Admin Dashboard: http://$VPN_IP:3007"
echo "API Endpoint:    http://$VPN_IP:8080"
echo ""
echo "------------------------------------------"
echo "  SECURITY KEYS (SAVE THESE!)"
echo "------------------------------------------"
echo "ADMIN USER:  $ADMIN_USERNAME"
echo "ADMIN PASS:  $ADMIN_PASSWORD"
echo "------------------------------------------"
echo "API_KEY:     $API_KEY"
echo "------------------------------------------"
echo "INTERNAL SECRETS (.env):"
echo "DB_PASSWORD: $DB_PASSWORD"
echo "JWT_SECRET:  $JWT_SECRET"

echo "------------------------------------------"
echo "These keys were automatically written to deployments/docker/.env"
echo ""
docker ps --format "table {{.Names}}	{{.Status}}	{{.Ports}}" | grep -i novusgate || true
