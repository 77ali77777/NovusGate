---
name: novusgate-rebuild-roadmap
description: NovusGate rebuild status — all phases done by 2026-10-15 (P5/P6 cancelled); what is still open and user hand-offs
metadata:
  node_type: memory
  type: project
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-15T13:10:12.557Z
---

Rebuild is split into P1–P8 (spec: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`). User decisions: nftables, current frontend kept (new UI kit dropped 2026-10-14), Center stays a separate Node.js tool; firewall: public SSH kept, port forwarding wanted, full-tunnel egress prepared in P3, IPv6 parity.

State on 2026-10-14: P1, P2a–P2d-3, P3a–P3b-2, P4a–P4c and all deferred review minors done on branch `rebuild/plans` (P2c-2 cancelled by the user; B10 Center join-vpn moved to P7). The user pushed the branch; it is not merged into main.

Open decisions closed 2026-10-14 (user answers): PostgreSQL published on 127.0.0.1 only (admin-VPN DB access now via SSH tunnel); Allow IP never opens admin/API ports 3007/5432/8080/8443 (nft compile guard + iptables mangle chain NOVUSGATE-ADMIN v4/v6 + API 400); `/health` checks only with X-API-Key or a session. `.env` files untracked and ignored. CI workflow prepared at `docs/ci/ci.yml` (agent cannot write `.github/`).

Decision 2026-10-14: the user rejected the new UI kit after a full clickable parity mockup (https://claude.ai/artifact/T3qJP3n5KZBgunekRtTSi1). The current frontend and design stay; P5 (UI kit) and P6 (page rewrite) are cancelled. Remaining UI work (B13, B15 frontend, P3c firewall UI, P8 UI parts) is done in the existing web/src style, no new UI packages.

State on 2026-10-15: frontend bugs (B13, toasts), P3c Advanced tab, P7 Center and P8 (full tunnel, traffic history, manual backups, Telegram notifications) done; last commit bf4a7cf. Later on 2026-10-15 also done: fail2ban logrotate copytruncate, Center preflight + scripts/*.sh extraction, Firewall Live (dynamic dropped sets, counters, conntrack) and History (fw_history, diff, confirmable restore). Decided NOT to do: Center job-log persistence (user: passwords in output). Then also done: fail2ban logs to /var/log/novusgate via drop-ins (the copytruncate conffile edit was replaced, conffile risk), Network Policies matrix, System Rules tab. No planned work left; only user hand-offs. Second review fixes 2026-10-15 (last 7c4fa65): iptables-mode VPN drop/reject rules now enforced via chain NOVUSGATE-VPN (user-approved behaviour change: rules that were silently dead start blocking after Update), policy matrix moved to backend GET /api/v1/firewall/policy-matrix, recidive backend=auto + log file pre-created. Open minor: operator-set fail2ban logtarget is overridden (documented). Later 2026-10-15 (last ad3b99d): user reversed two decisions — Center job logs ARE kept (data/jobs, unmasked, unlimited) and the non-design parts of P5/P6 were done in the current design: i18n az/en (12 namespaces, tests/i18n.test.mjs scanner), OpenAPI-generated web types (npm run gen:api + drift test), ErrorBoundary, Audit page + audit middleware, Sessions, Network detail, Topology. UI kit/Radix/react-hook-form/zod still not done. Nothing verified on a real server.

State end of 2026-10-15: P9a/b/c (groups+roles, limit profiles, quota) and P10a (server admin with step-up, client DNS, Server page) done on `feature/p9-control`, each with an opus review whose findings were fixed; web is biome 0 + TS strict. Locally fast-forwarded feature → rebuild/plans → main at d97b5d9 (user approved "İkisi də"); NOT pushed. Host commands of P10a never ran on a real host (test container cannot nsenter to a host). Playwright browser tests get foreign trusted clicks (likely another session sharing the browser): run flows inside one browser_evaluate.

User hand-offs still open: push main/rebuild/plans/feature, copy `docs/ci/ci.yml` to `.github/workflows/`, rotate API_KEY (old key is in git history of web/.env), add MASTER_KEY on existing servers, run staging runbooks in `docs/runbooks/` (Ubuntu 22.04, kernel 5.15, systemd 249), P9d (blocky) and P10b (staging) need the user's go.

**Why:** the user drives phase by phase ("davam", "hamsini tammayana kimi davam et") and wants nothing small left behind.
**How to apply:** check `git log` and `docs/active-context.md` first. See [[wsl-docker-shim-dollar-expansion]] for running tests.
