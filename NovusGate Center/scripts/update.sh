
#!/bin/bash
set -e
@@SHELL_HELPERS@@
INSTALL_DIR="/opt/NovusGate"
TEMP_DIR="/tmp/NovusGate_update"
BACKUP_DIR="/var/backups/novusgate/update-$(date +%Y%m%d-%H%M%S)"
set -E # the ERR trap below also fires inside functions
@@CLEAN_INSTALL_DIR_FN@@
# wait_healthy waits until the control plane answers /health
# (HEALTH_TRIES tries, 2 s apart; 30 = one minute).
wait_healthy() {
  command -v curl > /dev/null 2>&1 || { echo "  (curl missing: health not checked)"; return 0; }
  local i
  for i in $(seq 1 "${HEALTH_TRIES:-30}"); do
    if curl -fsS -m 3 http://127.0.0.1:8080/health > /dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

# report_health warns when the hub came up degraded (/health still answers
# 200 then) or the panel container is not running; the update is kept.
report_health() {
  local body web
  body=$(curl -fsS -m 3 http://127.0.0.1:8080/health 2>/dev/null || true)
  case "$body" in
    *'"degraded"'*) echo "  [WARN] The hub is up but degraded: $body" ;;
  esac
  web=$(docker inspect -f '{{.State.Running}}' novusgate-web 2>/dev/null || true)
  [ "$web" = "true" ] || echo "  [WARN] The panel container novusgate-web is not running (docker logs novusgate-web)."
}

# rollback restores the code and .env saved in BACKUP_DIR and starts that
# version again. The database is not restored: migrations only add, so the
# previous version runs on the newer schema; BACKUP_DIR/db.sql is kept for a
# manual restore.
rollback() {
  trap - ERR
  echo ""
  echo "[ROLLBACK] The update failed; restoring the previous version from $BACKUP_DIR ..."
  cd /
  clean_install_dir "$INSTALL_DIR"
  tar -xzf "$BACKUP_DIR/code.tar.gz" -C "$INSTALL_DIR"
  # An older version reads /var/log/fail2ban.log: undo the log move the new
  # setup-firewall.sh may already have made.
  if ! grep -q /var/log/novusgate "$INSTALL_DIR/server/deployments/docker/docker-compose.yml" 2>/dev/null; then
    rm -f /etc/fail2ban/fail2ban.d/novusgate.local
    rm -f /etc/logrotate.d/novusgate-fail2ban
    [ -f /etc/fail2ban/jail.d/novusgate.local ] && sed -i '/^\[recidive\]/,$d' /etc/fail2ban/jail.d/novusgate.local
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      fail2ban-client set logtarget /var/log/fail2ban.log > /dev/null 2>&1 || true
      systemctl reload fail2ban 2>/dev/null || true
    fi
  fi
  cd "$INSTALL_DIR"
  compose -f server/deployments/docker/docker-compose.yml up -d --build --force-recreate || true
  if wait_healthy; then
    echo "[ROLLBACK] The previous version is running again."
  else
    echo "[ROLLBACK] The previous version did not become healthy either; check 'docker ps' and the container logs."
  fi
  exit 1
}

# Ensure MASTER_KEY exists (seals node private keys; added in P4c)
@@ENSURE_MASTER_KEY@@

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
  SERVER_DIFF=$(diff -rq "$TEMP_DIR/server" "$INSTALL_DIR/server" \
    --exclude='.env' \
    --exclude='data' \
    --exclude='*.log' \
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
  WEB_DIFF=$(diff -rq "$TEMP_DIR/web" "$INSTALL_DIR/web" \
    --exclude='.env' \
    --exclude='node_modules' \
    --exclude='dist' \
    --exclude='*.log' \
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

# Backup before anything changes: the rollback source, and a manual restore
# point (code with .env, WireGuard configs, database dump).
echo "[backup] Saving the current version to $BACKUP_DIR ..."
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/code.tar.gz" -C "$INSTALL_DIR" --exclude='./server/data' --exclude='./data' .
tar -czf "$BACKUP_DIR/wireguard.tar.gz" -C /etc wireguard 2>/dev/null || true
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx novusgate-postgres; then
  ENV_FILE="$INSTALL_DIR/server/deployments/docker/.env"
  DB_USER_V=$(grep -E '^DB_USER=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  DB_NAME_V=$(grep -E '^DB_NAME=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  docker exec novusgate-postgres pg_dump -U "${DB_USER_V:-novusgate}" "${DB_NAME_V:-novusgate}" > "$BACKUP_DIR/db.sql" \
    || echo "  (database dump failed; the code backup is still taken)"
fi
trap rollback ERR

# 3. Copy files (preserving .env and data)
echo "[3/6] Updating files..."
# rsync mirrors the new tree (deleted files go too); a plain copy would
# leave old files behind, and they could end up in the build.
command -v rsync &> /dev/null || apt_get install -y rsync
rsync -a --delete \
  --exclude='.env' \
  --exclude='server/deployments/docker/.env' \
  --exclude='web/.env' \
  --exclude='data/' \
  --exclude='*.log' \
  --exclude='admin-vpn.conf' \
  "$TEMP_DIR/" "$INSTALL_DIR/"

rm -rf "$TEMP_DIR"
cd "$INSTALL_DIR"

# 4. Rebuild only changed containers
echo "[4/6] Rebuilding changed containers..."

# Remove dangling images first to avoid conflicts
docker image prune -f 2>/dev/null || true

# The new images are built while the old containers keep running; only the
# swap (force-recreate) stops them, so the panel and API are down for seconds
# instead of the whole build. Volumes and server/data are never removed.
if [ "$DOCKER_CHANGED" = true ]; then
  echo "  Docker config changed - rebuilding every image, then recreating the stack"
  compose -f server/deployments/docker/docker-compose.yml build --no-cache
  compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --remove-orphans
elif [ "$SERVER_CHANGED" = true ] && [ "$WEB_CHANGED" = true ]; then
  echo "  Rebuilding: control-plane, web"
  compose -f server/deployments/docker/docker-compose.yml build --no-cache control-plane web
  compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps control-plane web
elif [ "$SERVER_CHANGED" = true ]; then
  echo "  Rebuilding: control-plane only"
  compose -f server/deployments/docker/docker-compose.yml build --no-cache control-plane
  compose -f server/deployments/docker/docker-compose.yml up -d --force-recreate --no-deps control-plane
elif [ "$WEB_CHANGED" = true ]; then
  echo "  Rebuilding: web only"
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
  sed -i 's/\r$//' "$INSTALL_DIR/server/deployments/docker/setup-firewall.sh"
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

echo "[health] Waiting for the control plane..."
wait_healthy || { echo "[ERROR] The control plane did not answer /health within a minute."; rollback; }
trap - ERR
report_health
# Keep the five newest update backups.
ls -1dt /var/backups/novusgate/update-* 2>/dev/null | tail -n +6 | xargs -r rm -rf

echo ""
echo "=========================================="
echo "  UPDATE COMPLETE!"
if [ "$SERVER_CHANGED" = true ]; then echo "  ✅ Server rebuilt"; fi
if [ "$WEB_CHANGED" = true ]; then echo "  ✅ Web rebuilt"; fi
if [ "$SERVER_CHANGED" = false ] && [ "$WEB_CHANGED" = false ]; then echo "  ✅ Config updated (no rebuild needed)"; fi
echo "  ✅ .env preserved"
echo "  ✅ Database preserved"
echo "=========================================="
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -i novusgate || true
