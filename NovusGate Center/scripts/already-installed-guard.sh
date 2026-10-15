
if [ -f "$INSTALL_DIR/server/deployments/docker/.env" ]; then
  echo "[ERROR] NovusGate is already installed in $INSTALL_DIR."
  echo "Use Update (keeps everything) or Reinstall (keeps database and .env) instead."
  rm -f /tmp/NovusGate.tar.gz
  exit @@EXIT_ALREADY_INSTALLED@@
fi
