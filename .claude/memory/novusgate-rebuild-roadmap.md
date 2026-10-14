---
name: novusgate-rebuild-roadmap
description: "NovusGate rebuild status — P1–P4 done on rebuild/plans; open decisions closed 2026-10-14; next P5 UI kit after mockup approval; hand-offs"
metadata:
  type: project
---

Rebuild is split into P1–P8 (spec: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`). User decisions: nftables, fully new UI kit, Center stays a separate Node.js tool; firewall: public SSH kept, port forwarding wanted, full-tunnel egress prepared in P3, IPv6 parity.

State on 2026-10-14: P1, P2a–P2d-3, P3a–P3b-2, P4a–P4c and all deferred review minors done on branch `rebuild/plans` (P2c-2 cancelled by the user; B10 Center join-vpn moved to P7). The user pushed the branch; it is not merged into main.

Open decisions closed 2026-10-14 (user answers): PostgreSQL published on 127.0.0.1 only (admin-VPN DB access now via SSH tunnel); Allow IP never opens admin/API ports 3007/5432/8080/8443 (nft compile guard + iptables mangle chain NOVUSGATE-ADMIN v4/v6 + API 400); `/health` checks only with X-API-Key or a session. `.env` files untracked and ignored. CI workflow prepared at `docs/ci/ci.yml` (agent cannot write `.github/`).

P5 visual mockup awaiting user approval: https://claude.ai/artifact/T3qJP3n5KZBgunekRtTSi1 — rebuilt 2026-10-14 at the user's request as a full parity mockup (40 artboards: every page, modal, confirm, empty/error state of web/src, from a line-by-line inventory). User rule: a mockup must show every existing screen, modal, field and action, nothing missing. IBM Plex Sans/Mono, teal accent #0F766E / dark #2DD4BF.

User hand-offs still open: copy `docs/ci/ci.yml` to `.github/workflows/`, rotate API_KEY (old key is in git history of web/.env), add MASTER_KEY on existing servers, run staging runbooks in `docs/runbooks/`, merge to main.

**Why:** the user drives phase by phase ("davam", "hamsini tammayana kimi davam et") and wants nothing small left behind.
**How to apply:** check `git log` and `docs/active-context.md` first. See [[wsl-docker-shim-dollar-expansion]] for running tests.
