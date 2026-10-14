# P4c Node Key Encryption, Hidden Keys and Audit User Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- Node WireGuard private keys leave `nodes.labels`. They are stored in their own column, encrypted with AES-GCM under a master key from the environment, and are never returned by the API.
- Firewall audit entries record the panel user who made the change.

**Architecture:**
- A small package `internal/shared/secretbox` seals and opens values with AES-256-GCM.
- The store holds an optional `*secretbox.Box`. Values are written as:
  - `v1:<base64(nonce|ciphertext)>` when a master key is configured;
  - `plain:<key>` when it is not. Existing installs keep working, and the server warns at startup.
- `serve` runs an idempotent key migration at startup. It moves `labels.wireguard_private_key` into the column and re-seals `plain:` values once a key exists.
- Node JSON loses the label and gains `has_config`.
- `CreateFirewallAuditLog` takes the session user's ID.

**Tech Stack:** Go 1.23 stdlib `crypto/aes`, `crypto/cipher`; PostgreSQL 16; React/TS; Center (Node.js) install scripts.

**Spec:**
- Master spec §4.3: node private keys AES-GCM with a master key in env; `labels.wireguard_private_key` hidden in API responses; audit log gets `user_id`.
- User approval on 2026-10-14 ("P4 spec-dəki kimi").

## Global Constraints
- **Master key:** env `NOVUSGATE_MASTER_KEY`, 64 hex characters (32 bytes).
  - Compose passes `MASTER_KEY` from `.env`.
  - Center's install writes `MASTER_KEY=$(openssl rand -hex 32)`. Its reinstall/update keeps an existing `.env` and appends `MASTER_KEY` when it is missing.
  - An invalid value (wrong length, not hex) stops `serve` with an error. A missing value starts with a warning and `plain:` storage.
- **Never log or return a key.** `models.Node` gets `HasConfig bool json:"has_config"`. No field carries the key.
- **API contract change (approved with P4):**
  - node responses no longer contain `labels.wireguard_private_key`;
  - they gain `has_config` (true when the server holds the node's private key, so config, QR and install script are available).
- **Rollback:**
  - the migration is additive (`009_node_keys_and_audit_user.sql`);
  - `novusgate-server keys-to-labels` writes the decrypted keys back into labels (it needs the master key) before an older binary runs;
  - the down SQL then drops the column. Its header documents this order.
- **Environment:**
  - Go: `bash server/scripts/test-with-postgres.sh`;
  - Center: `node --test test/*.test.js` in `node:20-bookworm`;
  - web: the node:20 container check (`tsc`, `biome`).

## Review Focus
1. **A `plain:` value after a master key is configured.**
   - Expected: re-sealed at the next startup.
   - Pinned by `TestMigrateNodeKeysResealsPlain`.
2. **A wrong master key.**
   - Expected: decrypt fails with an error (500 on config), never garbage.
   - Pinned by `TestSecretboxWrongKey`.
3. **Checkin or update cannot plant or read the key** (labels never carry it).
   - Pinned by the P4b label filter plus `TestNodeJSONHasNoPrivateKey`.
4. **Startup migration runs twice.**
   - Expected: idempotent.
   - Pinned by `TestMigrateNodeKeysIdempotent`.
5. **Deleting the user of an audit entry.**
   - Expected: the entry stays, with `user_id` NULL (`ON DELETE SET NULL`).
   - Pinned by `TestAuditUserSetNullOnDelete`.

---

### Task 1: `secretbox`
**Files:** `server/internal/shared/secretbox/secretbox.go`, `secretbox_test.go`.

**Produces:**
- `type Box struct{ aead cipher.AEAD }`
- `func New(hexKey string) (*Box, error)`
- `func FromEnv() (*Box, error)`: nil, nil when unset
- `func Seal(b *Box, plaintext string) (string, error)`: `plain:` when b is nil
- `func Open(b *Box, stored string) (string, error)`: opens `v1:` (error if b is nil) and `plain:`

- [ ] **Step 1: Write failing tests.**
  - round trip;
  - two seals of the same value differ (random nonce);
  - a wrong key gives an error (`TestSecretboxWrongKey`);
  - nil box → `plain:` round trip;
  - bad key length or bad hex → error;
  - a `v1:` value with a nil box → error.
- [ ] **Step 2: Run.** Expected: build failure.
- [ ] **Step 3: Implement** with `aes.NewCipher` + `cipher.NewGCM`, a 12-byte random nonce and base64 std encoding.
- [ ] **Step 4: Run.** Expected: `ok`.
- [ ] **Step 5: Commit.** `feat: add AES-GCM secretbox for stored secrets`.

### Task 2: Schema and store
**Files:**
- `store/migrations_sql/009_node_keys_and_audit_user.sql`
- `store/migrations_rollback/009_node_keys_and_audit_user.down.sql`
- `store/node_keys.go`
- `store/node_keys_test.go`
- `store/store.go` (node SELECTs add `has_config`; `CreateFirewallAuditLog` gets `userID`)
- `shared/models/models.go` (`Node.HasConfig`)

```sql
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS private_key_enc TEXT;
ALTER TABLE firewall_audit_log ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL;
```

**Produces:**
- `func (s *Store) SetKeyBox(b *secretbox.Box)`
- `func (s *Store) SetNodePrivateKey(ctx, nodeID, key string) error`
- `func (s *Store) NodePrivateKey(ctx, nodeID string) (string, error)`: `""` when none
- `func (s *Store) MigrateNodeKeys(ctx) (moved, resealed int, err error)`
- `func (s *Store) RestoreNodeKeysToLabels(ctx) (int, error)`
- `CreateFirewallAuditLog(ctx, action string, details map[string]interface{}, userIP, userID string) error`: an empty `userID` is stored as NULL

- [ ] **Step 1: Failing tests.**
  - set/get round trip with a box: the DB column starts with `v1:` and does not contain the key;
  - `HasConfig` is true from `GetNode` and `ListNodes`;
  - migrate: a node with a label key → the column is set and the label is gone; a second run moves 0 (`TestMigrateNodeKeysIdempotent`);
  - `plain:` → `v1:` after `SetKeyBox` (`TestMigrateNodeKeysResealsPlain`);
  - restore puts the label back;
  - audit `user_id` is stored, and NULL after the user is deleted (`TestAuditUserSetNullOnDelete`).
- [ ] **Step 2: Run.** Expected: build failure.
- [ ] **Step 3: Implement.**
  - The node SELECTs gain `private_key_enc IS NOT NULL` scanned into `HasConfig`.
  - Migrate in one transaction per node. Read the label, then `UPDATE nodes SET private_key_enc=$2, labels = labels - 'wireguard_private_key'`.
  - Reseal rows `LIKE 'plain:%'` when a box is set.
  - Update the audit insert column list.
  - Fix the 4 audit callers in `api/rest` for compile (pass `""`; Task 3 passes the user).
- [ ] **Step 4: Run.** Expected: all `ok`.
- [ ] **Step 5: Commit.** `feat: store node keys encrypted outside labels`.

### Task 3: Server wiring
**Files:**
- `config_handlers.go`: create sets the key via the store; config, QR and install read via `NodePrivateKey`; a missing key → 404 `no_private_key`; a decrypt error → 500
- `firewall_handlers.go`: audit callers pass the session user ID
- `cmd/control-plane/main.go`: `FromEnv` → `SetKeyBox`; startup `MigrateNodeKeys` with a log line; a warning when there is no key; the `keys-to-labels` subcommand
- `contract_test.go`: the seed sets the key via `SetNodePrivateKey`, not labels
- snapshots
- `api/rest/node_keys_test.go`

- [ ] **Step 1: Failing tests.**
  - `TestNodeJSONHasNoPrivateKey`: create a server via the API, then GET the node; the body has no `wireguard_private_key` and has `has_config: true`; GET config still contains `PrivateKey = `.
  - The audit test: a VPN rule created via the API → the audit row's `user_id` is the session user.
- [ ] **Step 2: Run.** Expected: failures (the label is present, `user_id` is NULL).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Update snapshots.**
  - Expected diffs: node bodies lose `"wireguard_private_key": "<key>"` from labels and gain `"has_config": true/false`; `openapi.json` gains `has_config`.
  - Nothing else.
  - Run the suite: all `ok`.
- [ ] **Step 5: Commit.** `feat: hide node private keys and record audit users`.

### Task 4: Web, compose, Center
- [ ] **Web:**
  - `types/index.ts` Node gets `has_config: boolean`;
  - `Nodes.tsx:203` uses `node.has_config`.
  - Container check: tsc 0, biome ≤ baseline.
- [ ] **Compose:** control-plane env `NOVUSGATE_MASTER_KEY: ${MASTER_KEY:-}`.
- [ ] **Center `lib/scripts.js`:**
  - the install heredoc and the "config provided" heredoc add `MASTER_KEY=$(openssl rand -hex 32)`;
  - the keep-existing-env branch appends it when it is missing (same style as `WG_SERVER_ENDPOINT`).
  - Run Center tests in node:20: all pass. Add a test asserting both generated scripts contain `MASTER_KEY=`, if `test/` has script-content tests (check first).
- [ ] **Commit.** `feat: master key for node secrets in web, compose and Center`.

### Task 5: Docs
- [ ] `docs/security.md`, `docs/data-model.md` (009), `docs/deployment.md` (`MASTER_KEY`, rollback order, loss of the key = node configs must be re-created), `docs/api.md` (`has_config`, `no_private_key`), `docs/active-context.md`.
- [ ] Run the suite and commit: `docs: document node key encryption and audit users`.

## Out of scope
- Encrypting `networks.server_private_key`: not in the spec. It is already hidden from JSON (`json:"-"`). Record it as a follow-up.
- Rotating the master key.
