#!/bin/bash
# Functional check of limit profiles (P9b) with real packets: speed limits
# measured with iperf3, the connection cap, and schedules. Runs
# TestLimitsWithRealTraffic in a container with NET_ADMIN and SYS_ADMIN (no
# --privileged); network namespaces stand in for a node and a server. The
# container runs in Asia/Baku (UTC+4): schedules must still match, because
# every nft the control plane runs uses TZ=UTC.
# Run from Git Bash:
#   bash server/scripts/limits-functional-check.sh
set -euo pipefail
SERVER_DIR="${SERVER_DIR:-/mnt/c/Users/Administrator/Desktop/NovusGate/server}"
MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --sysctl net.ipv4.ip_forward=1 -e TZ=Asia/Baku -v gomod:/go/pkg/mod -v "$SERVER_DIR":/src -w /src golang:1.23 \
  bash -c 'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tzdata nftables iproute2 iperf3 ncat iputils-ping procps >/dev/null 2>&1 && NFT_FUNC=1 go test ./internal/netctl/nft/ -run TestLimitsWithRealTraffic -count=1 -v 2>&1 | tail -30'
