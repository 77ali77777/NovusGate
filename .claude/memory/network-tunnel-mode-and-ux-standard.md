---
name: network-tunnel-mode-and-ux-standard
description: "User wants tunnel mode chosen per network (split VPN / full tunnel), nodes inherit it; every panel section must be understandable at professional-product UX level"
metadata:
  node_type: memory
  type: project
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-16T11:26:50.937Z
---

User decisions (2026-10-16):
- Creating a network asks for its type: **VPN (split)** or **Full tunnel**. Nodes created in that network follow the network's mode by default (a per-node override may remain as an exception).
- Turning the nftables engine on/off must be possible from the panel by an admin (not by editing .env by hand); see the confirm/auto-revert pattern of the sysctl change.
- The network policy matrix must explain itself (from/to axes, reason visible in each cell, legend), not only in a hover title.
- General bar: every section should be managed the way professional systems do it, with UI/UX a non-expert understands. Audit by looking at the real pages, then report → plan → approval → full fix.

**Why:** the user found the panel hard to understand (matrix, engine-off tabs) and wants the product to feel professional.
**How to apply:** before adding or changing a feature, ask "would a non-expert admin understand this screen?"; pair with [[help-tip-every-input]].
