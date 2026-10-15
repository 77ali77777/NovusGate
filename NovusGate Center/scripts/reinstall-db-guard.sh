
if [ -f "$INSTALL_DIR/server/data/postgres/PG_VERSION" ] \
  && [ ! -f "$INSTALL_DIR/server/deployments/docker/.env" ] \
  && [ ! -f /tmp/NovusGate.env.bak ]; then
  echo "[ERROR] An existing database was found in $INSTALL_DIR/server/data but no .env to go with it."
  echo "Restore server/deployments/docker/.env (or /tmp/NovusGate.env.bak) first, or remove server/data to start fresh."
  exit @@EXIT_DB_WITHOUT_ENV@@
fi
