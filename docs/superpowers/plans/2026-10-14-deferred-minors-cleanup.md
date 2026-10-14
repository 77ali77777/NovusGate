# Deferred Minors Cleanup Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every "minor (deferred)" finding left by the P1–P4 final reviews. The user asked on 2026-10-14 that nothing be left: "heç bir kiçik heç nə qalmasın".

**Source:** every `minor (deferred)` line in this session's transcript, plus the P4a/P4b/P4c final reviews. Items that later phases already fixed are listed as **verified-closed**, with the code that closes them.

**Method:**
- Behaviour fixes are TDD: a failing test first, then the fix.
- Doc and runbook items are edited directly.
- Items that would break a project rule are closed with a written reason. Example: a performance change without a measurement (CLAUDE.md §3).
- One commit per batch. Every batch ends with `bash server/scripts/test-with-postgres.sh` green. Web and Center batches also run their container checks.

## Verified-closed (no work)
- **P3a M2** (guard does not unmap IPv4-mapped addresses): `nft/guard.go:28` unmaps.
- **P3a M3** (`CheckProtection` not enforced): `firewall/engine.go:224` calls it on every propose path.
- **P3b-1 M5** (`isVPNInterface` uses a "wg" prefix): replaced by `vpnInterfaces(rs)` from `rs.Networks` (`nft/compile.go:374`).
- **P2d-2 M-2** (206 undocumented): `docExtraResponses` (P2d-3).

## Batch A — Auth (P4a review)
- [x] A1: the password update and the revocation of other sessions run in one transaction (`store.ChangePassword`).
- [x] A2: a session user deleted mid-request gets 401 `invalid_token`, not 500.
- [x] A3: `handleUpdatePassword` and `handleLogout` without a session → 401 (explicit guard).
- [x] A4: limiter memory and CPU:
  - prune expired entries at most once a minute, in O(n);
  - hard cap the tracked keys (oldest dropped);
  - key IPv6 by its /64.
- [x] A5: a successful login removes only its own attempt; it no longer clears the IP's failures.
- [x] A6: web `ChangePasswordCard` stops sending `username`.
- [x] A7: remove the stale `AuthMiddleware` comments.
- [x] A8: unknown usernames run bcrypt against a dummy hash, so their timing matches.

## Batch B — Enrollment (P4b review)
- [x] B1: checkin decodes and validates the body and finds the node **before** it consumes the token; the script stops at once on 401 with "token used or expired".
- [x] B2: the hostname in the checkin JSON is reduced to `[A-Za-z0-9._-]`.
- [x] B3: the script installs `curl` when it is missing, even if `wg` exists.
- [x] B4: the token goes to curl through a 0600 header file (`-H @file`), not argv.
- [x] B5: creating a token deletes used or expired tokens older than a day.
- [x] B6: `apiErrorMessage` reads error bodies that arrive as text (`responseType: 'text'`).
- [x] B7: install-script modal:
  - a Regenerate button;
  - its own copied state;
  - a response for a node that is no longer shown is ignored.
- [x] B8: the API key must match `[A-Za-z0-9._~-]+`; otherwise serve refuses to start (nginx template safety). Documented.
- [x] B9: `web/DEVELOPER_GUIDE*.md` drop `VITE_API_URL`/`VITE_API_KEY`; `useWebSocket` defaults to the page's own origin. `web/.env.example` → **user** (`.env*` writes are machine-denied).

## Batch C — Node keys (P4c review)
- [x] C1: an empty legacy label is not migrated (it is dropped from labels, no column value).
- [x] C2: the reseal counter counts `RowsAffected`.
- [x] C3: the ciphertext is bound to its node ID as AES-GCM additional data (`v1` format unchanged otherwise; not deployed yet).
- [x] C4: Center `MASTER_KEY` falls back to `/dev/urandom`; an empty `MASTER_KEY=` line is replaced.
- [x] C5: create-server writes the node and its sealed key in one INSERT.
- [x] C6: `secretbox.IsPlain` is removed (unused).

## Batch D — API surface and OpenAPI (P2d reviews)
- [x] D1 (M-3): `GET /debug/wireguard/{id}` 404 uses the unified error body.
- [x] D2 (M-4): GET routes also answer HEAD (no body).
- [x] D3 (M-5): `/api` without a slash and `/api/...` with a trailing slash → JSON 404, documented.
- [x] D4 (M-1): nullable `$ref` is emitted as `{type: object, nullable, allOf}`.
- [x] D5 (P2d-3 M-2): `ssh_ports` and `egress_interface` are not documented as nullable (optional only).
- [x] D6 (M-6): `assertMatchesSpec` checks the Content-Type of media-type operations.
- [x] D7 (M-8):
  - query parameters documented;
  - an `X-API-Key` security scheme;
  - `format: binary` for the QR PNG;
  - an enum for `NodeStatus`.
- [x] D8 (M-9): `handleAPIFallback` does not clone the request per method.
- [x] D9: a test that every `docExtraResponses` key names a `docOps` entry.
- [x] D10 (P2a #2): `docs/api.md` scopes the error format to `/api` responses (SPA and 301 excluded).
- [x] D11 (P2b #9): mux's path-cleaning 301s are logged (logging wraps the router, not only matched routes).

## Batch E — Server internals (P2a–P2c reviews)
- [x] E1 (#10): fail2ban log read errors other than "not found" are logged and returned as an `error` field.
- [x] E2 (#4): `parseIgnoreIPList` keeps dot-less hostnames (`localhost`).
- [x] E3 (#5): networks narrower than /30 are rejected (`hubAddress` has no room for hub plus peer).
- [x] E4 (#5): the reconciler `Run` recovers from a panic in `RunOnce` and keeps running.
- [x] E5 (#6): shutdown waits for a running reconcile tick; wg commands get a timeout.
- [x] E6 (#7): `/health` uses a light query (interface names only).
- [x] E7 (#7): the shadow-mode "unknown peer" and "would change" warnings are logged once per change, not every tick.
- [x] E8 (#3): two nodes with one public key: the reconciler keeps the active one and reports the conflict instead of flapping.
- [x] E9 (#8): the PUT /nodes reactivation adds the peer with its full allowed IPs (gateway routes), not only /32.
- [x] E10 (#4): a panic after a partial write does not append an error body.
- [x] E11 (#6): the `captureLogs` test helper restores `log.SetOutput`.
- [x] E12 (#6): the `network_create` golden pins `WG_SERVER_ENDPOINT` (`t.Setenv`).
- [x] E13 (#7): `newContractServer` refuses a database whose name does not look like a test database.
- [x] E14 (#8): snapshot UUID normalisation numbers each distinct ID (`<uuid-1>`…), so wrong relations show.
- [x] E15 (#9): PUT /nodes peer add/remove has a handler test with a fake manager.
- [x] E16 (#9 web): password and user cards show the API message, with the fixed text only as fallback.
- [x] E17: sync logs each added peer, `skipped` excludes nodes without a key, and the `loadNetworks` error branches have tests.
- [x] E18 (#4): the contract normaliser leaves the example time in the `invalid_expires_at` message.
- [x] E19 (#1): release note — rebuild web and control plane together.

## Batch F — Firewall (P3 reviews)
- [x] F1 (M10): kernel `nft -c` test covers the edge rulesets (empty, IPv6-only, forwards, egress) across versions in `nft-versions-check.sh`.
- [x] F2 (M10): revert while a rollback timer is armed does not reload the old snapshot.
- [x] F3 (M4): a narrower ban under a shorter cover is re-applied when the cover expires (reconcile scheduled at the cover's expiry).
- [x] F4 (M6): `ErrNotReady` retries back off and stop logging after the first warning per failure.
- [ ] F5 (M8): the boot file drops already-expired timeouts (elements with `expires_at` in the past are not written).
- [x] F6 (M9): `setup-firewall.sh` strips a trailing `# comment` from `FIREWALL_ENGINE`.
- [x] F7 (M9): VPN drop/reject rules that cannot be converted are reported (warning in apply response and log), not silently skipped.
- [x] F8: `parseRuleLine`:
  - ignores `dpt:` inside `/* … */` comments;
  - has tests for numeric+opt, `-f`/`!f`, a DROP target and udp+opt;
  - loses the redundant `< 9` guard. (the guard was already gone after P2a; closed)

## Batch G — Docs and runbooks
- [x] G1 (M3): runbook — `netfilter-persistent save` also saves fail2ban chains.
- [x] G2 (M4): runbook step 5 — Update reruns `setup-firewall.sh` only when `server/docker` changed; run it by hand otherwise.
- [x] G3 (M7): runbook — after the P3b-1 update, restart control-plane once `setup-firewall` has installed the unit.
- [x] G4 (M8): verified-closed — already in p3b2 runbook step 11 ("Məlum məhdudiyyət (M8)").
- [x] G5: verified-closed — already in p1 runbook step 3.
- [x] G6: the `.gitattributes` comment explains why testdata is LF.
- [x] G7: the active-context archive keeps full test commands (no `…`).

## Batch H — Center (P1 reviews)
- [x] H1: the UI shows the script's refusal reason instead of "[DONE] Error occurred."
- [x] H2: the container filter is case-insensitive, like the grep.
- [x] H3 (temp dirs removed; form values go through shellQuote and validateInstallConfig, tested with $, quotes and backticks): tests generate scripts with passwords containing `$`, `"` and `'`, and run `bash -n` on them; temp dirs are removed.
- [x] H4: a blank line removed from the archive error text; the SSH connection is closed in the outer catch.
- [x] H5: a test for a non-numeric `SSH_CONNECTION` field.
- [x] H6 (verified-closed: the archive already excludes server/data and every .env; web/.env is no longer used since P4b):
  - the restore branch generates `web/.env` when only the server `.env` existed;
  - `createProjectArchive` excludes `server/data`.
- [x] H7:
  - sshd is looked up in `/usr/sbin` as well;
  - its non-zero exit is tested;
  - case "abc" asserts 22 and DROP-last.
- [x] H8: the exec-error path has a unit test with a fake SSH client.

## Closed with a reason (not changed)
- **P3b M8 / F5** (boot file timeouts restart at boot): nftables has no absolute expiry, and the boot unit loads the last applied script as is. In nft mode the control plane reconciles at startup (`StartFirewall`: `MarkReady`, then `ReconcileOrRetry`) and recomputes every remaining timeout and drops expired allows. The window is only boot until the control plane starts (container `restart: always`).
- **P2b #10** (`statusRecorder` hides `io.ReaderFrom`): this is a performance-only change. Nothing measures it, and the SPA is served by nginx, not by Go. CLAUDE.md §3 forbids unmeasured optimisation.
- **Center** `--filter` asymmetry: covered by H2.
