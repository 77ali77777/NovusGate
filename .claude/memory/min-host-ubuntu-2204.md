---
name: min-host-ubuntu-2204
description: "NovusGate target hosts are Ubuntu 22.04+ / Debian 12+ only; old servers (20.04, Debian 11) are not used"
metadata:
  node_type: memory
  type: project
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-15T09:59:49.082Z
---

User decision 2026-10-15: no old servers; worst case Ubuntu 22.04 (kernel 5.15, nftables 1.0.2). Center preflight enforces Ubuntu 22.04+ / Debian 12+ (commit 323c177).

**Why:** the nft firewall, limit profiles and quotas need nftables 1.0.2+.
**How to apply:** don't spend effort on 20.04/Debian 11 compatibility; the remaining kernel risk is only "verify on a 22.04 (5.15) staging host", since functional tests ran on the WSL kernel. Related: [[novusgate-rebuild-roadmap]].
