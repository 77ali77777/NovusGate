#!/bin/bash
# Runs scripts/test-in-docker.sh against a disposable Postgres, so database
# tests (TEST_DATABASE_URL) run too. Run on the Windows dev machine from Git Bash:
#   bash server/scripts/test-with-postgres.sh
# SERVER_DIR is the server directory as seen by Docker inside WSL.
set -euo pipefail

SERVER_DIR="${SERVER_DIR:-/mnt/c/Users/Administrator/Desktop/NovusGate/server}"
NET=novusgate-test-net
PG=novusgate-test-pg

cleanup() {
  docker rm -f "$PG" > /dev/null 2>&1 || true
  docker network rm "$NET" > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NET" > /dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=ng -e POSTGRES_PASSWORD=ng -e POSTGRES_DB=ng postgres:16-alpine > /dev/null
for _ in $(seq 1 30); do
  if docker exec "$PG" pg_isready -U ng > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN --network "$NET" \
  -e TEST_DATABASE_URL="postgres://ng:ng@$PG:5432/ng?sslmode=disable" \
  -v gomod:/go/pkg/mod -v "$SERVER_DIR":/src -w /src \
  golang:1.23 bash scripts/test-in-docker.sh
