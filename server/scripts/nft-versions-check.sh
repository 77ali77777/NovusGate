#!/bin/bash
# Validates the golden rulesets with the nft parser of every supported host
# (Ubuntu 22.04 = 1.0.2, Debian bookworm = 1.0.6, Ubuntu 24.04 = 1.0.9) and
# checks that a snapshot listed by nft 1.0.9 (the control plane) loads with
# each of them (the host-side rollback and boot unit). NET_ADMIN only; each
# container uses its own network namespace. Run from Git Bash:
#   bash server/scripts/nft-versions-check.sh
set -euo pipefail
SERVER_DIR="${SERVER_DIR:-/mnt/c/Users/Administrator/Desktop/NovusGate/server}"
VOL=novusgate-nft-check
docker volume rm "$VOL" > /dev/null 2>&1 || true
docker volume create "$VOL" > /dev/null
trap 'docker volume rm "$VOL" > /dev/null 2>&1 || true' EXIT
run() {
  MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v "$SERVER_DIR":/src:ro -v "$VOL":/out \
    -e STEP="$2" "$1" bash /src/scripts/nft-versions-inner.sh
}
run ubuntu:24.04 snapshot
for img in ubuntu:22.04 debian:bookworm ubuntu:24.04; do
  run "$img" check
done
echo "NFT-VERSIONS-OK"
