---
name: novusgate-rebuild-roadmap
description: "NovusGate rebuild status — P1, P3a, P3b-1, P3b-2 done on branch rebuild/plans; next P2 backend core; user decisions recorded"
metadata:
  node_type: memory
  type: project
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-13T21:07:49.770Z
---

Rebuild is split into P1–P8 (spec: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`). User decisions: nftables, fully new UI kit, Center stays a separate Node.js tool; firewall: public SSH kept, port forwarding wanted, full-tunnel egress prepared in P3, IPv6 parity.

State on 2026-10-13: P1, P3a, P3b-1, P3b-2 implemented on branch `rebuild/plans` (user pushes; the agent cannot — `git push` is denied, `gh` not installed). Firewall spec: `docs/superpowers/specs/2026-10-13-p3-firewall-design.md` (§6b.4 "whole-address Allow IP opens admin ports" awaits the user's decision; legacy parity kept). P3c (firewall UI) waits for P5 (UI kit). Staging runbooks in `docs/runbooks/` are not yet run by the user. User hand-offs still open: create `.github/workflows/ci.yml` (writes under `.github` are denied), run the staging runbooks.

When the user only says "davam" without choosing, continue in roadmap order (P2 next) and say so.

**Why:** the user said the firewall is the most important part and asked for superpowers-driven plans; they execute with "davam" after each plan.
**How to apply:** check `git log` and `docs/active-context.md` first. See [[wsl-docker-shim-dollar-expansion]] for running tests.
