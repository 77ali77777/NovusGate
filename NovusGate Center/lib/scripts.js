// ============ INSTALL SCRIPTS ============

// shellQuote makes value one literal shell word: single-quoted, with each
// embedded single quote written as '\x27'. Every value from the Center's form
// goes through it.
function shellQuote(value) {
  return "'" + String(value).split("'").join("'\\''") + "'";
}

// Shell expression for a new MASTER_KEY (64 hex characters, seals node
// private keys); falls back to /dev/urandom when openssl is missing.
const MASTER_KEY_GEN = "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -t x1 | tr -d ' \\n')";

// Shell block that gives envFile a MASTER_KEY when it has none or an empty
// one. An existing key is never replaced: keys sealed with it would be lost.
const ensureMasterKey = (envFile) => `
if [ -f "${envFile}" ] && ! grep -q "^MASTER_KEY=." "${envFile}"; then
  sed -i '/^MASTER_KEY=$/d' "${envFile}"
  echo "MASTER_KEY=${MASTER_KEY_GEN}" >> "${envFile}"
fi
`;

// Bash function that empties the install dir while keeping persistent state:
// the Postgres data directory (server/data, bind-mounted by docker-compose),
// a legacy top-level data/ directory and the admin VPN client config.
const CLEAN_INSTALL_DIR_FN = `
clean_install_dir() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  find "$dir" -mindepth 1 -maxdepth 1 ! -name 'server' ! -name 'data' ! -name 'admin-vpn.conf' -exec rm -rf {} +
  if [ -d "$dir/server" ]; then
    find "$dir/server" -mindepth 1 -maxdepth 1 ! -name 'data' -exec rm -rf {} +
  fi
}
`;

// Bash helpers every script starts with: compose() runs Docker Compose v2
// ("docker compose", what get.docker.com installs) and falls back to the v1
// binary; apt_get() waits up to 10 minutes for a held dpkg lock (e.g.
// unattended-upgrades on a fresh server) instead of failing at once.
const SHELL_HELPERS = `
compose() {
  if docker compose version > /dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}
apt_get() { apt-get -o DPkg::Lock::Timeout=600 "$@"; }
`;

// Exit code of the install script when NovusGate is already installed.
const EXIT_ALREADY_INSTALLED = 3;

// A fresh install regenerates the database password and the wg0 server key,
// which would lock the control plane out of the existing database and break
// every VPN client. Existing installs must use Update or Reinstall instead.
const ALREADY_INSTALLED_GUARD = `
if [ -f "$INSTALL_DIR/server/deployments/docker/.env" ]; then
  echo "[ERROR] NovusGate is already installed in $INSTALL_DIR."
  echo "Use Update (keeps everything) or Reinstall (keeps database and .env) instead."
  rm -f /tmp/NovusGate.tar.gz
  exit ${EXIT_ALREADY_INSTALLED}
fi
`;

// Exit code of the reinstall script when a database exists without its .env.
const EXIT_DB_WITHOUT_ENV = 4;

// Reinstall keeps server/data, so it must also keep the credentials that
// database was created with. Without .env (or its /tmp backup) new secrets
// would lock the control plane out of the existing database.
const REINSTALL_DB_GUARD = `
if [ -f "$INSTALL_DIR/server/data/postgres/PG_VERSION" ] \\
  && [ ! -f "$INSTALL_DIR/server/deployments/docker/.env" ] \\
  && [ ! -f /tmp/NovusGate.env.bak ]; then
  echo "[ERROR] An existing database was found in $INSTALL_DIR/server/data but no .env to go with it."
  echo "Restore server/deployments/docker/.env (or /tmp/NovusGate.env.bak) first, or remove server/data to start fresh."
  exit ${EXIT_DB_WITHOUT_ENV}
fi
`;

const GENERATE_INSTALL_SCRIPT = (config) => `
#!/bin/bash
set -e
${SHELL_HELPERS}

INSTALL_DIR="/opt/NovusGate"
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'
${ALREADY_INSTALLED_GUARD}
# Configuration Variables
ADMIN_USERNAME=${shellQuote(config.adminUsername || 'admin')}
ADMIN_PASSWORD=${shellQuote(config.adminPassword || '')} # Empty means auto-generate
VPN_IP=${shellQuote(config.vpnIp || '10.99.0.1')}
VPN_SUBNET=${shellQuote(config.vpnIp ? config.vpnIp.replace(/\.\d+$/, '.0/24') : '10.99.0.0/24')}
VPN_CLIENT_IP=${shellQuote(config.vpnIp ? config.vpnIp.replace(/\.\d+$/, '.2') : '10.99.0.2')}

# Database Config
DB_NAME=${shellQuote(config.dbName || 'NovusGate')}
DB_USER=${shellQuote(config.dbUser || 'NovusGate')}
DB_PASSWORD=${shellQuote(config.dbPassword || '')} # Empty means auto-generate

log_info() { echo -e "\${GREEN}[INFO]\${NC} $1"; }
log_warn() { echo -e "\${YELLOW}[WARN]\${NC} $1"; }
log_error() { echo -e "\${RED}[ERROR]\${NC} $1"; }

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
  openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -t x1 | tr -d ' \n'
}

API_KEY=$(generate_secret)
JWT_SECRET=$(generate_secret)
# Seals node private keys in the database (64 hex characters).
MASTER_KEY=${MASTER_KEY_GEN}

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
echo -e "\${GREEN}  INSTALLATION COMPLETE!\${NC}"
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
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -i novusgate || true
`;


const GENERATE_REINSTALL_SCRIPT = (config) => {
  // Config Defaults
  const DB_NAME = config.dbName || 'NovusGate';
  const DB_USER = config.dbUser || 'NovusGate';
  const DB_PASS = config.dbPassword || ''; // If empty, generate or keep old?
  const ADMIN_USER = config.adminUsername || 'admin';
  const ADMIN_PASS = config.adminPassword || '';
  // Removed unused NET_NAME/CIDR
  // Calculate ADMIN_CIDR for .env
  const VPN_IP = config.vpnIp || '10.99.0.1'; 
  const ADMIN_CIDR = VPN_IP.replace(/\.\d+$/, '.0/24');

  return `
#!/bin/bash
set -e
${SHELL_HELPERS}

INSTALL_DIR="/opt/NovusGate"
${REINSTALL_DB_GUARD}
echo "=========================================="
echo "  NovusGate REINSTALL"
echo "=========================================="

# Backup .env before deleting
if [ -f "$INSTALL_DIR/server/deployments/docker/.env" ]; then
  echo "Preserving old config..."
  cp "$INSTALL_DIR/server/deployments/docker/.env" /tmp/NovusGate.env.bak
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
${CLEAN_INSTALL_DIR_FN}
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
${ensureMasterKey('server/deployments/docker/.env')}
else
  echo "Generating new keys (Config provided)..."
  generate_secret() { openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -t x1 | tr -d ' \\n'; }
  
  API_KEY=$(generate_secret)
  JWT_SECRET=$(generate_secret)
  MASTER_KEY=${MASTER_KEY_GEN}

  # Use provided or generate
  DB_NAME=${shellQuote(DB_NAME)}
  DB_USER=${shellQuote(DB_USER)}
  ADMIN_USERNAME=${shellQuote(ADMIN_USER)}
  ADMIN_CIDR=${shellQuote(ADMIN_CIDR)}
  DB_PASSWORD=${shellQuote(DB_PASS)}
  if [ -z "$DB_PASSWORD" ]; then
     DB_PASSWORD=$(generate_secret)
  fi

  ADMIN_PASSWORD=${shellQuote(ADMIN_PASS)}
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

# Ensure Fail2Ban is installed
if ! command -v fail2ban-client &> /dev/null; then
  echo "Installing Fail2Ban..."
  apt_get update -qq
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

  systemctl enable fail2ban
  systemctl restart fail2ban
  echo "Fail2Ban installed ✓"
fi

# Setup Firewall (re-run to ensure rules match new config if relevant, though mostly static)
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  # Fix Windows CRLF line endings
  sed -i 's/\\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
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
`;
};

// ============ HELPERS ============

const UNINSTALL_SCRIPT = `
#!/bin/bash
set -e
${SHELL_HELPERS}
INSTALL_DIR="/opt/NovusGate"

echo "=========================================="
echo "  NovusGate DEEP UNINSTALL"
echo "  WARNING: This will delete ALL data"
echo "=========================================="

echo "[1/5] Stopping Docker services..."
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  cd "$INSTALL_DIR"
  compose -f server/deployments/docker/docker-compose.yml down -v --rmi all --remove-orphans 2>/dev/null || true
fi

# Fallback: kill any NovusGate containers
docker ps --format "{{.ID}} {{.Names}}" | grep -i novusgate | awk '{print $1}' | xargs -r docker stop || true
docker ps -a --format "{{.ID}} {{.Names}}" | grep -i novusgate | awk '{print $1}' | xargs -r docker rm -f || true

echo "[2/5] Cleaning WireGuard Interfaces..."
# Stop Admin VPN
systemctl stop wg-quick@wg1 2>/dev/null || true
systemctl disable wg-quick@wg1 2>/dev/null || true
ip link delete wg1 2>/dev/null || true
rm -f /etc/wireguard/wg1.conf

# Stop Node VPN (Admin Network now on wg0)
systemctl stop wg-quick@wg0 2>/dev/null || true
systemctl disable wg-quick@wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true
rm -f /etc/wireguard/wg0.conf

echo "[3/5] Flushing Firewall Rules..."
# Reset iptables to default ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
# IPv6: only the admin port guard from setup-firewall.sh
if command -v ip6tables &> /dev/null; then
    ip6tables -t mangle -D PREROUTING -p tcp -m multiport --dports 3007,5432,8080,8443 -j NOVUSGATE-ADMIN 2>/dev/null || true
    ip6tables -t mangle -F NOVUSGATE-ADMIN 2>/dev/null || true
    ip6tables -t mangle -X NOVUSGATE-ADMIN 2>/dev/null || true
fi

# Save clean state
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
fi

echo "[4/5] Removing Files..."
rm -rf "$INSTALL_DIR"

echo "[5/5] Cleaning Docker Resources..."
docker system prune -af --volumes 2>/dev/null || true

echo "[DONE] Cleanup Complete!"
echo "Server is ready for a fresh install."
`;

const UPDATE_SCRIPT = `
#!/bin/bash
set -e
${SHELL_HELPERS}
INSTALL_DIR="/opt/NovusGate"
TEMP_DIR="/tmp/NovusGate_update"

# Ensure MASTER_KEY exists (seals node private keys; added in P4c)
${ensureMasterKey('$INSTALL_DIR/server/deployments/docker/.env')}

echo "=========================================="
echo "  NovusGate SMART UPDATE v2.0"
echo "  Only changed files & containers updated"
echo "=========================================="

# 1. Extract new code to temp dir
echo "[1/6] Extracting new files..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
tar -xzf /tmp/NovusGate.tar.gz -C "$TEMP_DIR"
rm -f /tmp/NovusGate.tar.gz

# 2. Detect what changed
echo "[2/6] Detecting changes..."

SERVER_CHANGED=false
WEB_CHANGED=false
DOCKER_CHANGED=false

# Check server/ changes (Go code)
if [ -d "$INSTALL_DIR/server" ]; then
  SERVER_DIFF=$(diff -rq "$TEMP_DIR/server" "$INSTALL_DIR/server" \\
    --exclude='.env' \\
    --exclude='data' \\
    --exclude='*.log' \\
    2>/dev/null | grep -v "Only in $INSTALL_DIR" || true)
  if [ -n "$SERVER_DIFF" ]; then
    SERVER_CHANGED=true
    echo "  📦 Server code changed"
  fi
else
  SERVER_CHANGED=true
  echo "  📦 Server code is new"
fi

# Check web/ changes (React code)
if [ -d "$INSTALL_DIR/web" ]; then
  WEB_DIFF=$(diff -rq "$TEMP_DIR/web" "$INSTALL_DIR/web" \\
    --exclude='.env' \\
    --exclude='node_modules' \\
    --exclude='dist' \\
    --exclude='*.log' \\
    2>/dev/null | grep -v "Only in $INSTALL_DIR" || true)
  if [ -n "$WEB_DIFF" ]; then
    WEB_CHANGED=true
    echo "  🌐 Web code changed"
  fi
else
  WEB_CHANGED=true
  echo "  🌐 Web code is new"
fi

# Check docker-compose or Dockerfile changes
if [ -f "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" ]; then
  if ! diff -q "$TEMP_DIR/server/deployments/docker/docker-compose.yml" "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" > /dev/null 2>&1; then
    DOCKER_CHANGED=true
    echo "  🐳 Docker config changed"
  fi
  if ! diff -q "$TEMP_DIR/server/deployments/docker/Dockerfile.control-plane" "$INSTALL_DIR/server/deployments/docker/Dockerfile.control-plane" > /dev/null 2>&1; then
    SERVER_CHANGED=true
    echo "  🐳 Server Dockerfile changed"
  fi
fi

if [ -f "$TEMP_DIR/web/Dockerfile" ] && [ -f "$INSTALL_DIR/web/Dockerfile" ]; then
  if ! diff -q "$TEMP_DIR/web/Dockerfile" "$INSTALL_DIR/web/Dockerfile" > /dev/null 2>&1; then
    WEB_CHANGED=true
    echo "  🐳 Web Dockerfile changed"
  fi
fi

# If nothing changed
if [ "$SERVER_CHANGED" = false ] && [ "$WEB_CHANGED" = false ] && [ "$DOCKER_CHANGED" = false ]; then
  echo ""
  echo "  ✅ No changes detected! System is up to date."
  rm -rf "$TEMP_DIR"
  exit 0
fi

# 3. Copy files (preserving .env and data)
echo "[3/6] Updating files..."
if command -v rsync &> /dev/null; then
  rsync -a --delete \\
    --exclude='.env' \\
    --exclude='server/deployments/docker/.env' \\
    --exclude='web/.env' \\
    --exclude='data/' \\
    --exclude='*.log' \\
    --exclude='admin-vpn.conf' \\
    "$TEMP_DIR/" "$INSTALL_DIR/"
else
  # Backup .env files
  [ -f "$INSTALL_DIR/server/deployments/docker/.env" ] && cp "$INSTALL_DIR/server/deployments/docker/.env" /tmp/NovusGate.env.bak
  [ -f "$INSTALL_DIR/web/.env" ] && cp "$INSTALL_DIR/web/.env" /tmp/NovusGate.web.env.bak
  
  # Copy files
  cp -r "$TEMP_DIR"/* "$INSTALL_DIR/"
  
  # Restore .env files
  [ -f "/tmp/NovusGate.env.bak" ] && mv /tmp/NovusGate.env.bak "$INSTALL_DIR/server/deployments/docker/.env"
  [ -f "/tmp/NovusGate.web.env.bak" ] && mv /tmp/NovusGate.web.env.bak "$INSTALL_DIR/web/.env"
fi

rm -rf "$TEMP_DIR"
cd "$INSTALL_DIR"

# 4. Rebuild only changed containers
echo "[4/6] Rebuilding changed containers..."

# Remove dangling images first to avoid conflicts
docker image prune -f 2>/dev/null || true

if [ "$DOCKER_CHANGED" = true ]; then
  echo "  Docker config changed - full rebuild required"
  compose -f server/deployments/docker/docker-compose.yml down --rmi local 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml up -d --build --force-recreate
elif [ "$SERVER_CHANGED" = true ] && [ "$WEB_CHANGED" = true ]; then
  echo "  Rebuilding: control-plane, web"
  compose -f server/deployments/docker/docker-compose.yml stop control-plane web 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml rm -f control-plane web 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml build --no-cache control-plane web
  compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps control-plane web
elif [ "$SERVER_CHANGED" = true ]; then
  echo "  Rebuilding: control-plane only"
  compose -f server/deployments/docker/docker-compose.yml stop control-plane 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml rm -f control-plane 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml build --no-cache control-plane
  compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps control-plane
elif [ "$WEB_CHANGED" = true ]; then
  echo "  Rebuilding: web only"
  compose -f server/deployments/docker/docker-compose.yml stop web 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml rm -f web 2>/dev/null || true
  compose -f server/deployments/docker/docker-compose.yml build --no-cache web
  compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps web
fi

# 5. Run migrations if server changed
echo "[5/6] Checking database..."
if [ "$SERVER_CHANGED" = true ]; then
  sleep 5
  compose -f server/deployments/docker/docker-compose.yml exec -T control-plane ./novusgate-server migrate 2>&1 || echo "Migration skipped"
else
  echo "  Server unchanged - skipping migration"
fi

# 6. Apply Firewall (only if setup script changed)
echo "[6/6] Checking firewall..."
if [ -f "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh" ]; then
  sed -i 's/\\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  chmod +x "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  # Only run if file was in the changed set
  if [ "$SERVER_CHANGED" = true ] || [ "$DOCKER_CHANGED" = true ]; then
    "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
  else
    echo "  Firewall unchanged - skipping"
  fi
fi

# Ensure all containers running
compose -f server/deployments/docker/docker-compose.yml up -d

echo ""
echo "=========================================="
echo "  UPDATE COMPLETE!"
if [ "$SERVER_CHANGED" = true ]; then echo "  ✅ Server rebuilt"; fi
if [ "$WEB_CHANGED" = true ]; then echo "  ✅ Web rebuilt"; fi
if [ "$SERVER_CHANGED" = false ] && [ "$WEB_CHANGED" = false ]; then echo "  ✅ Config updated (no rebuild needed)"; fi
echo "  ✅ .env preserved"
echo "  ✅ Database preserved"
echo "=========================================="
docker ps --format "table {{.Names}}\\t{{.Status}}" | grep -i novusgate || true
`;

// Database-only migration script (no file changes)
const DATABASE_MIGRATE_SCRIPT = `
#!/bin/bash
set -e
${SHELL_HELPERS}
INSTALL_DIR="/opt/NovusGate"

echo "=========================================="
echo "  NovusGate DATABASE MIGRATION"
echo "  Files PRESERVED"
echo "=========================================="

cd "$INSTALL_DIR"

echo "[1/2] Checking database migrations..."
compose -f server/deployments/docker/docker-compose.yml exec -T control-plane ./novusgate-server migrate

echo ""
echo "=========================================="
echo "  ✅ Database updated!"
echo "=========================================="
`;

module.exports = {
  shellQuote,
  SHELL_HELPERS,
  MASTER_KEY_GEN,
  ensureMasterKey,
  CLEAN_INSTALL_DIR_FN,
  EXIT_ALREADY_INSTALLED,
  ALREADY_INSTALLED_GUARD,
  EXIT_DB_WITHOUT_ENV,
  REINSTALL_DB_GUARD,
  GENERATE_INSTALL_SCRIPT,
  GENERATE_REINSTALL_SCRIPT,
  UNINSTALL_SCRIPT,
  UPDATE_SCRIPT,
  DATABASE_MIGRATE_SCRIPT,
};
