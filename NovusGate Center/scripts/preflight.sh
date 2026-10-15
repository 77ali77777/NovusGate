
preflight() {
  local os_release="${OS_RELEASE:-/etc/os-release}" meminfo="${MEMINFO:-/proc/meminfo}" dir="${PREFLIGHT_DIR:-/opt}"
  local errors=0 id="" version="" major arch mem_kb free_kb port
  if [ -f "$os_release" ]; then
    id="$(. "$os_release" 2>/dev/null; echo "$ID")"
    version="$(. "$os_release" 2>/dev/null; echo "$VERSION_ID")"
  fi
  major="${version%%.*}"
  case "$id" in
    ubuntu)
      if ! [ "$major" -ge 20 ] 2>/dev/null; then
        echo "[ERROR] Ubuntu $version is too old: NovusGate needs Ubuntu 20.04 or newer."; errors=$((errors + 1))
      fi ;;
    debian)
      if ! [ "$major" -ge 11 ] 2>/dev/null; then
        echo "[ERROR] Debian $version is too old: NovusGate needs Debian 11 or newer."; errors=$((errors + 1))
      fi ;;
    *)
      echo "[ERROR] Unsupported OS '${id:-unknown}': NovusGate installs on Ubuntu 20.04+ or Debian 11+."; errors=$((errors + 1)) ;;
  esac

  arch="$(uname -m)"
  case "$arch" in
    x86_64|aarch64) ;;
    *) echo "[ERROR] CPU architecture $arch is not supported: x86_64 or aarch64 is needed."; errors=$((errors + 1)) ;;
  esac

  mem_kb="$(awk '/^MemTotal:/ {print $2}' "$meminfo" 2>/dev/null)"
  if [ -n "$mem_kb" ] && [ "$mem_kb" -lt 900000 ]; then
    echo "[ERROR] $((mem_kb / 1024)) MB RAM: NovusGate needs at least 1 GB."; errors=$((errors + 1))
  elif [ -n "$mem_kb" ] && [ "$mem_kb" -lt 1900000 ]; then
    echo "[WARN] $((mem_kb / 1024)) MB RAM: it works, but building the panel image is slow below 2 GB."
  fi

  [ -d "$dir" ] || dir=/
  free_kb="$(df -Pk "$dir" 2>/dev/null | awk 'NR == 2 {print $4}')"
  if [ -n "$free_kb" ] && [ "$free_kb" -lt 3145728 ]; then
    echo "[ERROR] $((free_kb / 1024)) MB free disk on $dir: NovusGate needs at least 3 GB for its images."; errors=$((errors + 1))
  fi

  if command -v ss > /dev/null 2>&1; then
    for port in 3007 5432 8080 8443; do
      if [ -n "$(ss -Hltn "sport = :$port" 2>/dev/null)" ]; then
        echo "[ERROR] TCP port $port is already in use (see: ss -ltnp 'sport = :$port')."; errors=$((errors + 1))
      fi
    done
    if [ -n "$(ss -Hlun "sport = :51820" 2>/dev/null)" ]; then
      # wg0 itself (e.g. left by a failed install): the installer replaces it.
      if [ "$(wg show wg0 listen-port 2>/dev/null)" = "51820" ]; then
        echo "[WARN] wg0 already listens on UDP 51820; the installer will replace it."
      else
        echo "[ERROR] UDP port 51820 is already in use (see: ss -lunp 'sport = :51820')."; errors=$((errors + 1))
      fi
    fi
  else
    echo "[WARN] ss not found: ports 3007, 5432, 8080, 8443 and 51820/udp were not checked."
  fi

  if ! command -v systemctl > /dev/null 2>&1; then
    echo "[ERROR] systemd is needed (the firewall boot unit and fail2ban run as services)."; errors=$((errors + 1))
  fi

  if [ "$errors" -gt 0 ]; then
    echo "[ERROR] Preflight found $errors problem(s); nothing was changed on this server."
    return 1
  fi
  echo "[INFO] Preflight checks passed ✓"
}
