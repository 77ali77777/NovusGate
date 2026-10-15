
compose() {
  if docker compose version > /dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}
apt_get() { apt-get -o DPkg::Lock::Timeout=600 "$@"; }
