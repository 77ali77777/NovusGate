#!/bin/bash
# Runs inside a distro container for nft-versions-check.sh.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null
apt-get install -y -qq nftables > /dev/null
echo "== $(. /etc/os-release && echo "$PRETTY_NAME"): $(nft --version)"
cd /src/internal/netctl/nft/testdata
case "$STEP" in
  snapshot)
    nft -f full.nft
    nft list table inet novusgate > /out/snapshot.nft
    ;;
  check)
    for f in *.nft; do
      nft -c -f "$f"
      echo "ok $f"
    done
    { echo "table inet novusgate"; echo "delete table inet novusgate"; cat /out/snapshot.nft; } > /tmp/restore.nft
    nft -c -f /tmp/restore.nft
    echo "ok snapshot from nft 1.0.9"
    ;;
esac
