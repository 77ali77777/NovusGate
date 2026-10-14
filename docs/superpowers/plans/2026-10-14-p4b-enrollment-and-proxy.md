# P4b Enrollment Token and Same-Origin Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- A new Linux node can be enrolled with a script copied from the panel.
- The script checks in over the VPN with a one-time, 15-minute enrollment token. No port is opened to the internet.
- The web panel talks to the API through its own nginx (same origin), which removes the mixed content (B23) and keeps `VITE_API_KEY` out of the JS bundle.

**Architecture:**
- `GET /nodes/{id}/install.sh` stays behind panel auth. Each call issues a fresh enrollment token (hash stored in `enrollment_tokens`) and embeds it in the script.
- The script, in order:
  1. writes `wg0.conf`;
  2. brings WireGuard up;
  3. calls `POST http://<hub address>:8080/api/v1/nodes/{id}/checkin` with `X-Enrollment-Token`, retrying until the tunnel answers.
- Both auth middlewares let exactly that request shape through. The handler then consumes the token atomically.
- nginx proxies `/api/` and `/health` to `127.0.0.1:8080`. It adds `X-API-Key` from its environment and `X-Real-IP`.
- The control plane trusts `X-Real-IP` only from loopback.

**Tech Stack:** Go 1.23, PostgreSQL 16, nginx (official image, `/etc/nginx/templates` envsubst), React/TypeScript.

**Spec:**
- Master spec §4.3: enrollment token, nginx proxy, no `VITE_API_URL`; §7 B9, B23.
- User decision on 2026-10-14: the install script is copied from the panel, no public port.
- P4a plan (sessions, `clientIP`).

## Global Constraints
- **No public port.** The enrollment checkin is reached over the VPN (8080 is accepted on `wg+`).
- **Enrollment token:**
  - 32 random bytes, hex;
  - only its SHA-256 is stored;
  - valid 15 minutes, for one node, one use (`used_at`);
  - a new `install.sh` fetch issues a new token, and older unused tokens stay valid until they expire.
- **Checkin auth:** a panel session works as before. Without a session, `X-Enrollment-Token` must match an unused, unexpired token of that node, otherwise `401 invalid_enrollment_token`.
- **Checkin labels:** keys starting with `wireguard_` are ignored. Before this, a checkin could overwrite `wireguard_private_key`.
- **Same origin:**
  - the web calls `/api/v1` relative to its own origin;
  - `VITE_API_URL` and `VITE_API_KEY` are no longer read;
  - Go stops sending `Access-Control-*` headers (no cross-origin browser client is left).
- **Out of P4b:**
  - B10 (Center `join-vpn`) moves to P7, which owns Center;
  - Center still writes `VITE_*` lines into `web/.env`, which are now ignored.
- **Migrations:** additive. `008_enrollment_tokens.sql` ships with its rollback.
- **Environment:**
  - Go: `bash server/scripts/test-with-postgres.sh`;
  - snapshots: `bash server/scripts/update-contracts.sh`;
  - web: the node:20 container check (copy of `web/`, `npm ci`, `tsc --noEmit`, `biome check`);
  - nginx: `nginx -t` in `nginx:alpine` with the rendered template.
- **No `.env*` edits** (machine deny). `web/.dockerignore` gains `.env` so the file never enters the image.

## Review Focus
1. **An enrollment token reused, expired, or used for another node.**
   - Expected: 401.
   - Pinned by `TestEnrollmentCheckin`.
2. **A request carrying `X-Enrollment-Token` to any path other than `POST /api/v1/nodes/{id}/checkin`.**
   - Expected: the header grants nothing.
   - Pinned by `TestEnrollmentHeaderOnlyOpensCheckin`.
3. **`X-Real-IP` sent by a non-loopback client.**
   - Expected: ignored by the login limiter.
   - Pinned by `TestClientIPTrustsOnlyLoopbackProxy`.
4. **The script's shell quoting.**
   - Expected: the config heredoc is quoted (`<<'WGCONF'`) so nothing in it expands, and the checkin body uses the `arch` key the API reads.
   - Pinned by `TestInstallScript`.
5. **nginx config validity, and the API key not entering the bundle.**
   - Pinned by `nginx -t`, and by a grep of the built bundle for the `VITE_API_KEY` reference.

---

### Task 1: Enrollment tokens (table + store)

**Files:**
- `store/migrations_sql/008_enrollment_tokens.sql`
- `store/migrations_rollback/008_enrollment_tokens.down.sql`
- `store/enrollment.go`
- `store/enrollment_test.go`

**Produces:**
- `func (s *Store) CreateEnrollmentToken(ctx, nodeID, tokenHash string, now time.Time, ttl time.Duration) error`
- `func (s *Store) ConsumeEnrollmentToken(ctx, nodeID, tokenHash string, now time.Time) (bool, error)`: atomic `UPDATE … SET used_at = now WHERE node_id AND token_hash AND used_at IS NULL AND expires_at > now`, reporting whether a row changed.

- [ ] **Step 1: Failing test**
  - Consume works once, then fails.
  - Consume fails for another node and for an expired token.
  - Deleting the node removes its tokens (cascade).
- [ ] **Step 2: Run.** Expected: build failure, undefined methods.
- [ ] **Step 3: Implement**

```sql
-- Migration: 008_enrollment_tokens.sql
-- Purpose: one-time node enrollment tokens (P4b). Only the SHA-256 is stored.
-- rollback: internal/controlplane/store/migrations_rollback/008_enrollment_tokens.down.sql
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_node ON enrollment_tokens(node_id);
```

The rollback is `BEGIN; DROP TABLE IF EXISTS enrollment_tokens; DELETE FROM schema_migrations WHERE version='008_enrollment_tokens.sql'; COMMIT;`.

- [ ] **Step 4: Run.** Expected: all `ok`.
- [ ] **Step 5: Commit.** `feat: add one-time enrollment tokens`.

### Task 2: Install script and enrollment checkin

**Files:**
- `api/rest/enrollment.go` (new)
- `config_handlers.go` (`handleNodeInstallScript`)
- `handlers.go` (`handleNodeCheckIn`, `APIKeyMiddleware`)
- `auth.go` (`authMiddleware`)
- `enrollment_test.go` (new)
- `openapi.go` (checkin summary)
- snapshots

**Produces:**
- `const enrollmentTTL = 15 * time.Minute`
- `func isEnrollmentCheckin(r *http.Request) bool`: method POST, path `^/api/v1/nodes/[^/]+/checkin$`, non-empty `X-Enrollment-Token`
- `func installScript(config, checkinURL, nodeID, token string) string`

- [ ] **Step 1: Failing tests** (`enrollment_test.go`)
  - **`TestInstallScript`.** GET `install.sh` with a session returns 200 `text/x-shellscript`. The body:
    - contains `<<'WGCONF'`;
    - contains `systemctl restart wg-quick@wg0` **before** the checkin;
    - checks in to `http://10.66.0.1:8080/api/v1/nodes/<id>/checkin` (hub of `10.66.0.0/24`);
    - sends `X-Enrollment-Token: <64 hex>` and `"arch"`.
  - **`TestEnrollmentCheckin`.** Take the token from the script with a regexp, then:
    - checkin with it and no session → 200;
    - the same token again → `401 invalid_enrollment_token`;
    - a token from the script of node A used on node B → 401;
    - an expired token (`authNow` moved 16 minutes) → 401.
  - **`TestEnrollmentHeaderOnlyOpensCheckin`.** `GET /api/v1/networks` and `GET /nodes/{id}` with only `X-Enrollment-Token` → 401.
  - **`TestCheckinIgnoresWireguardLabels`.** A checkin with `labels: {"wireguard_private_key":"x","mac_address":"m"}` keeps the stored key and adds `mac_address`.
- [ ] **Step 2: Run.** Expected: failures (the script has no token, checkin without a session is 401, labels are overwritten).
- [ ] **Step 3: Implement**
  - **`enrollment.go`:** `enrollmentTTL`, `isEnrollmentCheckin` (`checkinPathRe = regexp.MustCompile(`^/api/v1/nodes/[^/]+/checkin$`)`), `installScript`.
  - **Middlewares:**
    - `authMiddleware`: `if isEnrollmentCheckin(r) { next.ServeHTTP(w, r); return }` (the handler authenticates);
    - `APIKeyMiddleware`: the same skip.
  - **`handleNodeCheckIn`:** if `sessionFrom(r)` has no user:
    - `ok, err := s.store.ConsumeEnrollmentToken(ctx, id, hashToken(header), authNow())`;
    - when not `ok`, return `errorWithCode(401, "invalid_enrollment_token", "invalid or expired enrollment token")`;
    - do this **before** decoding.

    With or without a session, label keys with prefix `wireguard_` are skipped.
  - **`handleNodeInstallScript`:**
    - a nil network → 404;
    - hub address from `hubAddress(network.CIDR)`, cut at `/`;
    - `token := newSessionToken()`; `CreateEnrollmentToken(node.ID, hashToken(token), authNow(), enrollmentTTL)`;
    - write `installScript(config, "http://"+hub+":8080/api/v1/nodes/"+id+"/checkin", id, token)`.
  - **`installScript`:** steps are apt install, then `<<'WGCONF'` config, then `chmod 600`, then `systemctl enable` and `restart`, then a checkin loop of 30 tries, 2 s apart, using `curl -fsS --max-time 5`. The JSON body is built from `uname -m` and `hostname` via `printf` with `%s`.
  - **`openapi.go`:** the checkin summary mentions the enrollment header.
- [ ] **Step 4: Run, then update snapshots.** Expected: `host_checkin` unchanged (session path); all `ok`.
- [ ] **Step 5: Commit.** `feat: enroll nodes with a one-time token over the VPN`.

### Task 3: Same-origin proxy and trusted client IP

**Files:**
- `web/nginx.conf` → `web/nginx/default.conf.template`
- `web/Dockerfile`
- `web/.dockerignore`
- `server/deployments/docker/docker-compose.yml` (web service)
- `auth.go` (`clientIP`)
- `handlers.go` (`handleLogin` CORS lines, `APIKeyMiddleware` OPTIONS branch)
- `auth_test.go`

- [ ] **Step 1: Failing tests**
  - **`TestClientIPTrustsOnlyLoopbackProxy`:**
    - `RemoteAddr 127.0.0.1:x` + `X-Real-IP 203.0.113.5` → `203.0.113.5`;
    - `RemoteAddr 198.51.100.9:x` + the same header → `198.51.100.9`.
  - **`TestNoCORSHeaders`:** GET `/api/v1/networks` with a session has no `Access-Control-Allow-Origin` header.
- [ ] **Step 2: Run.** Expected: both fail.
- [ ] **Step 3: Implement**
  - **`clientIP`:** when the host is a loopback IP and `X-Real-IP` parses as an IP, return it.
  - **Remove CORS:**
    - the three `Access-Control-*` header blocks;
    - the OPTIONS early-returns in `authMiddleware` and `APIKeyMiddleware`;
    - the OPTIONS handling in `handleLogin`;
    - the route `.Methods("POST","OPTIONS")` → `.Methods("POST")`.
    - An OPTIONS request then gets the router's 405.
  - **`web/nginx/default.conf.template`:** the current server block plus:

```nginx
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-API-Key "${NOVUSGATE_API_KEY}";
        proxy_read_timeout 60s;
    }
    location = /health {
        proxy_pass http://127.0.0.1:8080;
    }
```

  - **`Dockerfile`:**
    - `COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template`;
    - remove the old `COPY nginx.conf`;
    - the cert comment says build time;
    - `ENV NOVUSGATE_API_KEY=""`.
  - **`.dockerignore`:** add `.env`, `.env.*`.
  - **compose web:** `environment: NOVUSGATE_API_KEY: ${API_KEY:-}`. Remove `API_URL` and the `web/.env` volume.
- [ ] **Step 4: Verify**
  - Go: all `ok`.
  - nginx: render the template with `envsubst` in `nginx:alpine` (`NOVUSGATE_API_KEY=test`), then run `nginx -t` with the self-signed cert generated in the container. Expected: `syntax is ok`.
  - Compose: `docker compose -f server/deployments/docker/docker-compose.yml config -q` (needs no env file? if it fails on a missing `.env`, record that and skip).
- [ ] **Step 5: Commit.** `feat: serve the API through the panel's nginx`.

### Task 4: Web — relative API, no bundled key, copyable install script

**Files:**
- `web/src/api/client.ts`
- `web/src/App.tsx`
- `web/src/vite-env.d.ts`
- `web/src/components/ServerConfigModal.tsx`

- [ ] **Step 1: Baseline.** Record tsc and biome counts in the container.
- [ ] **Step 2: Implement**
  - **`client.ts`:**
    - `baseURL: '/api/v1'`;
    - no `X-API-Key` header;
    - remove `API_URL`, `API_KEY` and the unused `getAuthHeaders`;
    - add `getNodeInstallScript(id): Promise<string>` (`responseType: 'text'`).
  - **`App.tsx`:** login `fetch('/api/v1/auth/login', …)`.
  - **`vite-env.d.ts`:** drop `VITE_API_URL` and `VITE_API_KEY`.
  - **`ServerConfigModal.tsx`, Linux tab:**
    - a "Generate install script" button fetches the script;
    - it shows the script in a `<pre>` with Copy and Download (`install-<node>.sh`);
    - a note: "Valid once, for 15 minutes. Run as root on the new server."
    - The old `curl … | bash` command is removed (it could never work).
- [ ] **Step 3: Verify.**
  - tsc exit 0, and the biome count is not higher than the baseline.
  - `npm run build` in the container, then `grep -r "X-API-Key" dist` → no match.
- [ ] **Step 4: Commit.** `feat: same-origin API client and copyable install script`.

### Task 5: Docs
- [ ] **`docs/api.md`:**
  - enrollment (install.sh token, checkin header, 401 code);
  - the CORS removal;
  - OPTIONS → 405.
- [ ] **`docs/security.md`:**
  - enrollment;
  - trusted proxy;
  - API key injected by nginx;
  - checkin label filter.
- [ ] **`docs/data-model.md`:** `enrollment_tokens`.
- [ ] **`docs/deployment.md`** (create): the web proxy, `NOVUSGATE_API_KEY`, and that `web/.env` is no longer used by the build.
- [ ] **`docs/active-context.md`:** move the oldest sessions to `docs/archive/` so the file stays under 400 lines, then add the P4b block and table row.
- [ ] Run `bash server/scripts/test-with-postgres.sh` → all `ok`; commit `docs: document enrollment and the same-origin proxy`.

## Out of scope
- **B10:** Center `join-vpn`, moved to P7.
- **P4c:** key encryption, hiding `wireguard_private_key`, audit `user_id`.
- **Rotating the API key or removing `web/.env` from git** — the user's call.
