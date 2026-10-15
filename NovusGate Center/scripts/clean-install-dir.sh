
clean_install_dir() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  find "$dir" -mindepth 1 -maxdepth 1 ! -name 'server' ! -name 'data' ! -name 'admin-vpn.conf' -exec rm -rf {} +
  if [ -d "$dir/server" ]; then
    find "$dir/server" -mindepth 1 -maxdepth 1 ! -name 'data' -exec rm -rf {} +
  fi
}
