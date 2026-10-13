---
name: wsl-docker-shim-dollar-expansion
description: "The Windows `docker` shim (wsl -d Ubuntu-24.04 docker \"$@\") expands `$`, `$?`, `$(...)` in arguments before the container sees them"
metadata:
  node_type: memory
  type: reference
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-13T14:42:05.335Z
---

On this machine `docker` from Git Bash goes through a shim to Docker inside WSL. Arguments are re-parsed by the WSL shell, so `docker run … sh -c 'echo $?'` prints the *host* value (always 0), not the container's. Observed 2026-10-13: `nft -c` failed but `exit=$?` showed 0; the P1 Task 6 "exit=0 instead of 124" ruling (R8) had the same cause.

**How to apply:** put shell logic in a script file and run `docker run … bash /path/script.sh` (NovusGate: `server/scripts/test-in-docker.sh`); keep `$` out of docker arguments. Mount paths as `/mnt/c/...` and prefix with `MSYS_NO_PATHCONV=1`. Read exit codes outside docker (`${PIPESTATUS[0]}` in Git Bash is reliable). Related: [[novusgate-rebuild-roadmap]].
