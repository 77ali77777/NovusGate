#!/bin/bash
# Runs the Go checks and tests inside a Linux container that has nftables,
# including the kernel checks (NFT_CHECK=1). Needs CAP_NET_ADMIN, e.g. from
# the repo root on the Windows dev machine:
#   MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v gomod:/go/pkg/mod \
#     -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src \
#     golang:1.23 bash scripts/test-in-docker.sh
# Keep shell logic in this file: the WSL docker shim expands "$" in arguments.
set -euo pipefail

if ! command -v nft > /dev/null 2>&1; then
  apt-get update -qq > /dev/null
  apt-get install -y -qq nftables > /dev/null
fi

# Only check paths that exist yet, so the script works while P3a is built task by task.
fmt_paths=()
vet_pkgs=(./internal/controlplane/api/rest/ ./cmd/control-plane/)
for p in ./internal/netctl ./internal/controlplane/firewall ./cmd/control-plane/firewall_cmd.go; do
  if [ -e "$p" ]; then
    fmt_paths+=("$p")
  fi
done
if [ -d ./internal/netctl ]; then vet_pkgs+=(./internal/netctl/...); fi
if [ -d ./internal/controlplane/firewall ]; then vet_pkgs+=(./internal/controlplane/firewall/); fi

if [ "${#fmt_paths[@]}" -gt 0 ]; then
  unformatted=$(gofmt -l "${fmt_paths[@]}")
  if [ -n "$unformatted" ]; then
    echo "gofmt needed:"
    echo "$unformatted"
    exit 1
  fi
fi

go vet "${vet_pkgs[@]}"
go build ./...
# -p 1: packages share one test database (TEST_DATABASE_URL) and must not run in parallel.
NFT_CHECK=1 go test -p 1 ./... -count=1
