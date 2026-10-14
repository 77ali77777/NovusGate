---
name: novusgate-rebuild-roadmap
description: "NovusGate rebuild status — P1–P4 done on rebuild/plans (P2c-2 cancelled); next P5 UI kit (mockup approval first); hand-offs"
metadata:
  node_type: memory
  type: project
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-14T02:04:16.797Z
---

Rebuild is split into P1–P8 (spec: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`). User decisions: nftables, fully new UI kit, Center stays a separate Node.js tool; firewall: public SSH kept, port forwarding wanted, full-tunnel egress prepared in P3, IPv6 parity.

State on 2026-10-14: P1, P3a, P3b-1, P3b-2, P2a (contract + bugs), P2b (slog/health), P2c (reconciler + expiry), P2d-1 (unified errors), P2d-2 (OpenAPI), P2d-3 (DTOs) done on branch `rebuild/plans`. The service layer was deliberately deferred (not in P2 acceptance criteria; P2 spec §5). P2c-2 cancelled by the user (restorePeers + reconciler suffice). User approved on 2026-10-14: P4 as in master spec §4.3 (sessions, rate limit, enrollment token, AES-GCM key encryption, hiding wireguard_private_key, nginx proxy) and all P5 npm packages from master spec §5 (UI mockup still needs approval). P4 done 2026-10-14 in three parts: P4a sessions, P4b enrollment (install script copied from the panel, no public port, checkin over the VPN) + same-origin nginx proxy, P4c AES-GCM node keys (MASTER_KEY) + has_config + audit user_id. B10 (Center join-vpn) moved to P7. Remaining: P5 UI kit (needs a visual mockup approved by the user first), P3c firewall UI (after P5), P6–P8.

User hand-offs still open: `git push` (agent cannot — denied; `gh` not installed), create `.github/workflows/ci.yml` (writes under `.github` are denied), run staging runbooks in `docs/runbooks/`. Open user decisions: P3 spec §6b.4 (whole-address Allow IP opens admin ports; legacy parity kept), whether `/health` details stay public.

On 2026-10-14 the user said "hamsini tammayana kimi davam et" — keep executing roadmap phases without asking between them; stop only for approvals (behaviour/API/DB/security/new package) and user-only steps.

**Why:** the user said the firewall is the most important part and asked for superpowers-driven plans; they execute with "davam" after each plan.
**How to apply:** check `git log` and `docs/active-context.md` first. See [[wsl-docker-shim-dollar-expansion]] for running tests.
