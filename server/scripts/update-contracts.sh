#!/bin/bash
# Usage from Git Bash: bash server/scripts/update-contracts.sh
set -euo pipefail
INNER=scripts/update-contracts-inner.sh bash "$(dirname "$0")/test-with-postgres.sh"
