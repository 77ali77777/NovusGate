---
name: novusgate-rebuild-roadmap
description: "NovusGate rebuild status (2026-10-13) — P1 done on branch rebuild/plans, P3 firewall spec + P3a plan written, user decisions recorded"
metadata:
  node_type: memory
  type: project
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-13T14:42:10.626Z
---

Rebuild is split into P1–P8 (spec: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`). User decisions: nftables, fully new UI kit, Center stays a separate Node.js tool; firewall: public SSH kept, port forwarding wanted, full-tunnel egress prepared in P3, IPv6 parity.

State on 2026-10-13: P1 Stabilization implemented on branch `rebuild/plans` (not pushed; `git push` is blocked for the agent — the user pushes and opens the PR; `gh` is not installed). P3 firewall spec and P3a engine plan committed (709d1a6); P3a code was prototyped and verified in scratch, not yet in the repo. User hand-offs still open: create `.github/workflows/ci.yml` (writes under `.github` are denied by permissions), run `docs/runbooks/p1-staging-acceptance.md` on a staging VM.

**Why:** the user said the firewall (SSH → network) is the most important part and asked for superpowers-driven plans.
**How to apply:** next steps are executing P3a (subagent-driven), then P3b; check `git log` and `docs/active-context.md` first. See [[wsl-docker-shim-dollar-expansion]] for running tests.
