#!/bin/bash
# Rewrites the REST contract snapshots (testdata/contract) against a real
# database. Review the git diff before committing: every change is an API change.
set -euo pipefail
cd /src
go test ./internal/controlplane/api/rest/ -run 'TestContract' -count=1 -update
