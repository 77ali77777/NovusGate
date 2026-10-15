
#!/bin/bash
set -e
@@SHELL_HELPERS@@
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
