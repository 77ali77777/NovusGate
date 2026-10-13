# P2a API Contract Freeze and Backend Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze today's REST response shapes in snapshot tests, then fix the backend bugs B14, B16, B21 and B22 and the DB-password log leak. Every fix shows up as a reviewed snapshot change.

**Architecture:**
- Package-level function variables become test seams for host commands and key generation, following the pattern of the existing `legacySSHPorts` and `adminPeers`.
- A contract test drives the real router against a real Postgres with seeded data. It normalizes volatile values and compares status, content type and body with golden files in `testdata/contract/`.
- Bug fixes are small pure functions with unit tests, plus snapshot updates.

**Tech Stack:** Go 1.23, gorilla/mux, PostgreSQL 16 (tests), React/TS (one helper).

**Spec:** `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md`, which elaborates the master spec `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` §3, §4.1 and §7.

## Global Constraints

- No new Go modules or npm packages. `wgctrl` is not added (spec §2.2).
- Response shapes change only where spec §3 lists a bug fix, and every such change is a golden-file diff in the same commit.
- Comments are in English. Docs are in Azerbaijani with full diacritics.
- Go runs only in Docker. Full suite: `bash server/scripts/test-with-postgres.sh` (gofmt on new files, vet, build, `go test -p 1`, real Postgres, `NFT_CHECK=1`).
- The WSL docker shim expands `$` and `|` in arguments, so shell logic goes in script files.
- No `--privileged` containers.
- The golang:1.23 test image has no `wg`, `iptables` or `fail2ban-client`. Tests must stub every host command anyway, never rely on that absence for correctness, and must not touch the machine running them.
- Commits carry no `Co-Authored-By`, "Claude", "Anthropic" or "AI generated" lines. One logical change per commit. `*.go`, `*.sh` and `*.json` test data are LF.
- `web/` has no JS test runner. Adding one is a new package, so it is out of scope: the frontend helper is verified with `tsc --noEmit`.

## Review Focus

1. **Volatile values leaking into snapshots.**
   - Volatile values: `last_seen`, time-based online/offline in `enrichNode`, expiry, ports chosen from existing rows.
   - Expected: running the contract test twice in a row gives identical files.
   - Pinned by Task 1 step 5: the suite is run twice after `-update`.
2. **Secrets in snapshots.**
   - Node `labels.wireguard_private_key` and the generated client config contain private keys.
   - Expected: the golden files contain no 44-character key.
   - Pinned by Task 1 step 5: grep of `testdata/contract` for `[A-Za-z0-9+/]{43}=` returns nothing.
3. **Missing or huge fail2ban log.**
   - Expected: history is `[]`, with no error and no panic.
   - Expected: only the last `limit` matching entries are kept in memory.
   - Pinned by Task 4 `TestParseFail2BanHistory` (limit) and the contract case with a missing log.
4. **Whitelist output variants.**
   - Variants: the tree format, a hostname entry, the empty answer ("No IP address/network is ignored"), and the legacy single-line format.
   - Expected: only entries are returned, never header words.
   - Pinned by Task 4 `TestParseIgnoreIPList`.
5. **Tiny networks.**
   - Covers `/30`, `/31` and `/32` CIDRs in `AllocateIP`.
   - Expected: a clean "no available IPs" error, never the broadcast address and never a panic.
   - Pinned by Task 5 `TestAllocateIPNeverReturnsBroadcast`.

---

## File Structure

| File | Responsibility |
|---|---|
| `server/internal/controlplane/api/rest/handlers.go` (modify) | seams `execHostCommand`, `execCommand`, `generateKeys`, `readFail2BanLog` as vars; B14/B16 handler wiring; B21 `hubAddress` |
| `server/internal/controlplane/api/rest/config_handlers.go` (modify) | use `generateKeys` |
| `server/internal/controlplane/api/rest/fail2ban_parse.go` (create) | pure parsers for history, log action and ignoreip |
| `server/internal/controlplane/api/rest/fail2ban_parse_test.go` (create) | parser tests |
| `server/internal/controlplane/api/rest/contract_test.go` (create) | contract harness and cases |
| `server/internal/controlplane/api/rest/testdata/contract/*.json` (create) | golden responses |
| `server/internal/controlplane/api/rest/firewall_handlers.go` (modify) | `parseRuleLine` (B22) |
| `server/internal/controlplane/store/store.go` (modify) | empty lists (B14), `AllocateIP` broadcast (B21) |
| `server/internal/controlplane/store/allocate_test.go` (create) | allocation tests |
| `server/internal/wireguard/manager.go` + `manager_test.go` (create test) | `parsePrivateKey` (B22) |
| `server/cmd/control-plane/main.go` + `main_test.go` (create) | `maskDatabaseURL` |
| `server/scripts/test-with-postgres.sh` (modify), `server/scripts/update-contracts.sh` + `update-contracts-inner.sh` (create) | golden update helper |
| `web/src/api/errors.ts` (create) + 5 call sites | read both error body forms |
| `docs/*` | docs |

---

### Task 1: Test seams and the contract snapshot harness

**Files:**
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`execCommand` at ~1183, `execHostCommand` at ~1191, `wireguard.GenerateKeys()` call at ~628)
- Modify: `server/internal/controlplane/api/rest/config_handlers.go:272`
- Modify: `server/scripts/test-with-postgres.sh`
- Create: `server/scripts/update-contracts.sh`, `server/scripts/update-contracts-inner.sh`
- Create: `server/internal/controlplane/api/rest/contract_test.go`, `server/internal/controlplane/api/rest/testdata/contract/*.json`

**Interfaces:**
- Produces:
  - package vars `execHostCommand`, `execCommand` (`func(name string, args ...string) (string, error)`) and `generateKeys` (`func() (string, string, error)`);
  - test helpers `newContractServer(t) (*Server, *store.Store)`, `seedContract(t, st) contractSeed`, `hostStub`, `assertContract(t, name, rec)`, `callAs(t, s, method, path, body string, auth bool)`;
  - script `server/scripts/update-contracts.sh`.

- [ ] **Step 1: Turn the host seams into variables** (behaviour unchanged)

In `handlers.go`, rename `func execCommand(` to `func runCommand(` and `func execHostCommand(` to `func runHostCommand(`. Then add, next to them:

```go
// execCommand and execHostCommand run commands in the container or on the
// host; tests replace them so no host command ever runs.
var (
	execCommand     = runCommand
	execHostCommand = runHostCommand
)

// generateKeys creates a WireGuard key pair (replaced in tests).
var generateKeys = wireguard.GenerateKeys
```

Replace `wireguard.GenerateKeys()` with `generateKeys()` in `handlers.go` (~628) and `config_handlers.go:272`. Then run `grep -rn "wireguard.GenerateKeys()" server/internal/controlplane`. Expected: no matches.

- [ ] **Step 2: Let the Postgres runner take another inner script**

In `server/scripts/test-with-postgres.sh`, add `INNER="${INNER:-scripts/test-in-docker.sh}"` below `PG=novusgate-test-pg`. Then change the last line to:

```bash
  golang:1.23 bash "$INNER"
```

Create `server/scripts/update-contracts-inner.sh`:

```bash
#!/bin/bash
# Rewrites the REST contract snapshots (testdata/contract) against a real
# database. Review the git diff before committing: every change is an API change.
set -euo pipefail
cd /src
go test ./internal/controlplane/api/rest/ -run 'TestContract' -count=1 -update
```

Create `server/scripts/update-contracts.sh`:

```bash
#!/bin/bash
# Usage from Git Bash: bash server/scripts/update-contracts.sh
set -euo pipefail
INNER=scripts/update-contracts-inner.sh bash "$(dirname "$0")/test-with-postgres.sh"
```

- [ ] **Step 3: Write the contract test** (`contract_test.go`)

```go
package rest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
	"golang.org/x/crypto/bcrypt"
)

var updateContract = flag.Bool("update", false, "rewrite testdata/contract snapshots")

var (
	uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	timeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)
	keyRe  = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
)

// hostStub answers host commands from a table and records every call.
type hostStub struct {
	out   map[string]string
	calls []string
}

func (h *hostStub) run(name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	h.calls = append(h.calls, cmd)
	if o, ok := h.out[cmd]; ok {
		return o, nil
	}
	return "", fmt.Errorf("stub: %q is not available", cmd)
}

// newContractServer builds a Server on TEST_DATABASE_URL with empty
// networks and users and every host command stubbed.
func newContractServer(t *testing.T) (*Server, *store.Store, *hostStub) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run database tests (scripts/test-with-postgres.sh)")
	}
	st, err := store.New(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"DELETE FROM networks", "DELETE FROM users"} { // nodes and VPN rules cascade
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	stub := &hostStub{out: map[string]string{}}
	origHost, origCmd, origKeys, origSSH := execHostCommand, execCommand, generateKeys, legacySSHPorts
	execHostCommand, execCommand = stub.run, stub.run
	generateKeys = func() (string, string, error) {
		return strings.Repeat("k", 43) + "=", strings.Repeat("K", 43) + "=", nil
	}
	legacySSHPorts = func() []uint16 { return []uint16{22} }
	t.Cleanup(func() { execHostCommand, execCommand, generateKeys, legacySSHPorts = origHost, origCmd, origKeys, origSSH })

	s := &Server{store: st, router: mux.NewRouter(), managers: map[string]*wireguard.Manager{},
		peerActivity: map[string]*PeerActivity{}}
	s.setupRoutes()
	return s, st, stub
}

type contractSeed struct {
	network, empty *models.Network
	node           *models.Node
}

func seedContract(t *testing.T, st *store.Store) contractSeed {
	t.Helper()
	ctx := context.Background()
	key := func(c string) string { return strings.Repeat(c, 43) + "=" }
	n := &models.Network{Name: "contract-net", CIDR: "10.66.0.0/24", ServerPrivateKey: key("s"),
		ServerPublicKey: key("S"), ServerEndpoint: "203.0.113.1", ListenPort: 51866, InterfaceName: "wg66"}
	e := &models.Network{Name: "contract-zempty", CIDR: "10.68.0.0/24", ServerPrivateKey: key("e"),
		ServerPublicKey: key("E"), ListenPort: 51868, InterfaceName: "wg68"}
	for _, x := range []*models.Network{n, e} {
		if err := st.CreateNetwork(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	node := &models.Node{NetworkID: n.ID, Name: "contract-node", VirtualIP: net.ParseIP("10.66.0.3"),
		PublicKey: key("N"), Labels: map[string]string{"wireguard_private_key": key("P")}, Status: models.NodeStatusOnline}
	if err := st.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("contract-pw-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &models.User{Username: "contract-user", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	return contractSeed{network: n, empty: e, node: node}
}

func callAs(t *testing.T, s *Server, method, path, body string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.200:5555"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func normalizeBody(body string) string {
	body = strings.ReplaceAll(body, adminToken, "<token>")
	body = uuidRe.ReplaceAllString(body, "<uuid>")
	body = timeRe.ReplaceAllString(body, "<time>")
	return keyRe.ReplaceAllString(body, "<key>")
}

// assertContract compares status, content type and normalized body with
// testdata/contract/<name>.json (rewritten with -update).
func assertContract(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	body := normalizeBody(rec.Body.String())
	snap := map[string]interface{}{"status": rec.Code, "content_type": ct, "body": body}
	var parsed interface{}
	if strings.HasPrefix(ct, "application/json") && json.Unmarshal([]byte(body), &parsed) == nil {
		snap["body"] = parsed
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "contract", name+".json")
	if *updateContract {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run bash server/scripts/update-contracts.sh)", name, err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("%s: API contract changed\n--- want\n%s--- got\n%s", name, want, buf.Bytes())
	}
}

// fail2banIgnoreTree is real `fail2ban-client get sshd ignoreip` output.
const fail2banIgnoreTree = "These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n|- ::1\n`- 10.99.0.0/24\n"

// TestContract freezes the response shapes of every endpoint that can run
// without a host. Order matters: reads first, then writes.
func TestContract(t *testing.T) {
	s, st, stub := newContractServer(t)
	seed := seedContract(t, st)
	stub.out["fail2ban-client get sshd ignoreip"] = fail2banIgnoreTree
	n, e, node := seed.network.ID, seed.empty.ID, seed.node.ID
	missing := "00000000-0000-4000-8000-000000000000"

	cases := []struct {
		name, method, path, body string
		auth                     bool
	}{
		{"health", "GET", "/health", "", false},
		{"unauthorized", "GET", "/api/v1/networks", "", false},
		{"login_ok", "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"contract-pw-1"}`, false},
		{"login_bad", "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"wrong"}`, false},
		{"networks_list", "GET", "/api/v1/networks", "", true},
		{"network_get", "GET", "/api/v1/networks/" + n, "", true},
		{"network_get_missing", "GET", "/api/v1/networks/" + missing, "", true},
		{"nodes_list", "GET", "/api/v1/networks/" + n + "/nodes", "", true},
		{"nodes_list_empty", "GET", "/api/v1/networks/" + e + "/nodes", "", true},
		{"node_get", "GET", "/api/v1/nodes/" + node, "", true},
		{"node_config", "GET", "/api/v1/nodes/" + node + "/config", "", true},
		{"stats_overview", "GET", "/api/v1/stats/overview", "", true},
		{"users_list", "GET", "/api/v1/users", "", true},
		{"vpn_rules_list", "GET", "/api/v1/firewall/vpn/rules", "", true},
		{"fail2ban_whitelist", "GET", "/api/v1/system/fail2ban/whitelist", "", true},
		{"fail2ban_history", "GET", "/api/v1/system/fail2ban/ban-history", "", true},
		{"network_create", "POST", "/api/v1/networks", `{"name":"contract-new","cidr":"10.67.0.0/24"}`, true},
		{"network_create_overlap", "POST", "/api/v1/networks", `{"name":"contract-overlap","cidr":"10.66.0.0/25"}`, true},
		{"network_create_bad_body", "POST", "/api/v1/networks", `{`, true},
		{"node_update", "PUT", "/api/v1/nodes/" + node, `{"name":"contract-node-renamed"}`, true},
		{"user_create", "POST", "/api/v1/users", `{"username":"contract-user-2","password":"contract-pw-2"}`, true},
		{"node_delete", "DELETE", "/api/v1/nodes/" + node, "", true},
	}
	for _, c := range cases {
		assertContract(t, c.name, callAs(t, s, c.method, c.path, c.body, c.auth))
	}
}
```

- [ ] **Step 4: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `FAIL` in `api/rest`, `TestContract`: `health: open testdata/contract/health.json: no such file or directory (run bash server/scripts/update-contracts.sh)`.

- [ ] **Step 5: Record today's contract and check it**

Run: `bash server/scripts/update-contracts.sh`. Expected: `ok …/api/rest`.

Then run all three checks:

| Command | Expected |
|---|---|
| `grep -rlE '[A-Za-z0-9+/]{43}=' server/internal/controlplane/api/rest/testdata/contract` | no output (no key leaked) |
| `grep -l '"body": null' server/internal/controlplane/api/rest/testdata/contract/*.json` | lists `nodes_list_empty.json` (B14 recorded as it is today) |
| `bash server/scripts/test-with-postgres.sh` **twice** | `ok` both times (no volatile value leaked) |

Read every golden file once and confirm that the content is today's behaviour and makes sense. `fail2ban_whitelist.json` must show the garbage words (B16) and `fail2ban_history.json` `"history": null`. If a value differs between the two runs, add its pattern to `normalizeBody` and repeat this step.

- [ ] **Step 6: Commit**

```bash
git add server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/config_handlers.go server/internal/controlplane/api/rest/contract_test.go server/internal/controlplane/api/rest/testdata/contract server/scripts/test-with-postgres.sh server/scripts/update-contracts.sh server/scripts/update-contracts-inner.sh
git commit -m "test: freeze REST API responses in contract snapshots"
```

---

### Task 2: Empty lists are `[]`, not `null` (B14)

**Files:**
- Modify: `server/internal/controlplane/store/store.go` (`ListNetworks` ~110, `ListNodes` ~238, `ListUsers` ~411)
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`handleFail2BanGetPermanentBans` `var bannedIPs` ~1960, `handleFail2BanHistory` `var history` ~2146)
- Modify: `server/internal/controlplane/api/rest/contract_test.go`
- Modify: `server/internal/controlplane/api/rest/testdata/contract/*.json` (regenerated)

- [ ] **Step 1: Write the failing test** (append to `contract_test.go`)

```go
// B14: an empty collection is [] (VPNRuleModal maps over it), never null.
func TestEmptyCollectionsAreArrays(t *testing.T) {
	s, st, stub := newContractServer(t)
	stub.out["iptables -L INPUT -n --line-numbers"] = "Chain INPUT (policy DROP)\nnum  target     prot opt source               destination\n"
	for path, want := range map[string]string{
		"/api/v1/networks": "[]",
		"/api/v1/users":    "[]",
	} {
		if got := strings.TrimSpace(callAs(t, s, "GET", path, "", true).Body.String()); got != want {
			t.Errorf("GET %s = %s, want %s", path, got, want)
		}
	}
	e := &models.Network{Name: "contract-empty", CIDR: "10.69.0.0/24", ListenPort: 51869, InterfaceName: "wg69"}
	if err := st.CreateNetwork(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(callAs(t, s, "GET", "/api/v1/networks/"+e.ID+"/nodes", "", true).Body.String()); got != "[]" {
		t.Errorf("nodes of an empty network = %s, want []", got)
	}
	for path, key := range map[string]string{
		"/api/v1/system/fail2ban/ban-history":    `"history":[]`,
		"/api/v1/system/fail2ban/permanent-bans": `"permanent_bans":[]`,
	} {
		if got := callAs(t, s, "GET", path, "", true).Body.String(); !strings.Contains(got, key) {
			t.Errorf("GET %s = %s, want %s", path, got, key)
		}
	}
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `FAIL: TestEmptyCollectionsAreArrays` with `GET /api/v1/networks = null, want []`, plus the users, nodes, history and permanent-bans lines.

- [ ] **Step 3: Implement**

Make these replacements:

| File | Old | New |
|---|---|---|
| `store.go` | `var networks []*models.Network` | `networks := []*models.Network{}` |
| `store.go` | `var nodes []*models.Node` | `nodes := []*models.Node{}` (in `ListNodes`) |
| `store.go` | `var users []*models.User` | `users := []*models.User{}` |
| `handlers.go` | `var bannedIPs []map[string]interface{}` | `bannedIPs := []map[string]interface{}{}` |
| `handlers.go` | `var history []map[string]string` | `history := []map[string]string{}` |

Before editing, run `grep -rn "nodes == nil\|networks == nil\|users == nil" server/internal`. Expected: no callers rely on `nil`. If any do, change them to `len(x) == 0` in this task.

- [ ] **Step 4: Run it and verify it passes, then update the contract**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `TestEmptyCollectionsAreArrays` passes. `TestContract` fails only on `nodes_list_empty` and `fail2ban_history` (`null` → `[]`).

Run: `bash server/scripts/update-contracts.sh`, then `git diff --stat server/internal/controlplane/api/rest/testdata/contract`.
Expected: exactly `nodes_list_empty.json` and `fail2ban_history.json` changed, each `null` → `[]`.

Run the suite again. Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/store/store.go server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/contract_test.go server/internal/controlplane/api/rest/testdata/contract
git commit -m "fix: return empty lists as [] instead of null"
```

---

### Task 3: Key parsing and iptables rule parsing (B22)

**Files:**
- Modify: `server/internal/wireguard/manager.go:180-192`
- Create: `server/internal/wireguard/manager_test.go`
- Modify: `server/internal/controlplane/api/rest/firewall_handlers.go` (`parseRuleLine`, ~202-268)
- Modify: `server/internal/controlplane/api/rest/firewall_portmatch_test.go`

**Interfaces:**
- Produces: `parsePrivateKey(config string) string` (wireguard package).
- Consumes: `isOptColumn(string) bool` (`firewall_handlers.go`, from P1).

- [ ] **Step 1: Write the failing tests**

`server/internal/wireguard/manager_test.go`:

```go
package wireguard

import (
	"strings"
	"testing"
)

// B22: base64 keys end in '='; splitting on every '=' dropped it.
func TestParsePrivateKeyKeepsPadding(t *testing.T) {
	key := strings.Repeat("a", 43) + "="
	for _, conf := range []string{
		"[Interface]\nPrivateKey = " + key + "\nListenPort = 51820\n",
		"[Interface]\nPrivateKey=" + key + "\n",
		"[Interface]\r\nPrivateKey =  " + key + "  \r\n",
	} {
		if got := parsePrivateKey(conf); got != key {
			t.Errorf("parsePrivateKey(%q) = %q, want %q", conf, got, key)
		}
	}
	if got := parsePrivateKey("[Interface]\nListenPort = 1\n"); got != "" {
		t.Errorf("no key must give empty, got %q", got)
	}
}
```

Append to `firewall_portmatch_test.go`:

```go
// B22: short lines must not panic, and iptables without the "opt" column
// (nf_tables builds) must still map in/out/source/destination correctly.
func TestParseRuleLine(t *testing.T) {
	for _, short := range []string{
		"1 0 0 ACCEPT all -- lo *",
		"1 0 0 ACCEPT all -- lo * 0.0.0.0/0",
	} {
		if r := parseRuleLine(short, "INPUT"); r != nil {
			t.Errorf("incomplete line %q must be skipped, got %+v", short, r)
		}
	}
	withOpt := parseRuleLine("3 10 600 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22", "INPUT")
	noOpt := parseRuleLine("3 10 600 ACCEPT 6 * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22", "INPUT")
	wg := parseRuleLine("5 3 180 ACCEPT 6 wg0 * 0.0.0.0/0 0.0.0.0/0 tcp dpt:3007", "INPUT")
	if withOpt == nil || withOpt.Port != "22" || withOpt.Source != "anywhere" || withOpt.Interface != "" {
		t.Fatalf("classic format: %+v", withOpt)
	}
	if noOpt == nil || noOpt.Port != "22" || noOpt.Source != "anywhere" || noOpt.Destination != "anywhere" || noOpt.Interface != "" {
		t.Fatalf("format without opt: %+v", noOpt)
	}
	if wg == nil || wg.InInterface != "wg0" || wg.Port != "3007" {
		t.Fatalf("interface without opt: %+v", wg)
	}
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected:
- the `wireguard` package fails to build with `undefined: parsePrivateKey`;
- in `api/rest`, `TestParseRuleLine` fails with `panic: runtime error: slice bounds out of range` (the 8- and 9-field lines) or a wrong field mapping (the format without opt).

- [ ] **Step 3: Implement**

3a. In `manager.go`, replace the loop at 180-192 with `privateKey := parsePrivateKey(string(content))` and add:

```go
// parsePrivateKey returns the PrivateKey value of a wg-quick config. Only
// the first '=' separates key and value: base64 keys end in '='.
func parsePrivateKey(config string) string {
	for _, line := range strings.Split(config, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "PrivateKey" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
```

Keep the following `if privateKey == "" {` branch unchanged.

3b. In `parseRuleLine`, replace everything from `fields := strings.Fields(line)` through the line `remaining := strings.Join(fields[10:], " ")` with:

```go
	fields := strings.Fields(line)
	// num pkts bytes target prot [opt] in out source destination [options...]
	// Newer iptables (nf_tables) omits the "opt" column.
	if len(fields) < 6 {
		return nil
	}
	in := 5
	if isOptColumn(fields[5]) {
		in = 6
	}
	if len(fields) < in+4 {
		return nil
	}
	lineNum, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	rule := &FirewallRule{Number: lineNum, Chain: chainName, Target: fields[3], Protocol: fields[4]}
	if fields[in] != "*" {
		rule.InInterface = fields[in]
		rule.Interface = fields[in]
	}
	if fields[in+1] != "*" {
		rule.OutInterface = fields[in+1]
		if rule.Interface == "" {
			rule.Interface = fields[in+1]
		}
	}
	rule.Source = fields[in+2]
	if rule.Source == "0.0.0.0/0" {
		rule.Source = "anywhere"
	}
	rule.Destination = fields[in+3]
	if rule.Destination == "0.0.0.0/0" {
		rule.Destination = "anywhere"
	}
	remaining := strings.Join(fields[in+4:], " ")
```

Keep the existing lines after it (`rule.Options = remaining`, `rule.Port = extractPort(remaining)`, `return rule`).

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`. `TestContract` is unchanged (these paths are not in it).

- [ ] **Step 5: Commit**

```bash
git add server/internal/wireguard/manager.go server/internal/wireguard/manager_test.go server/internal/controlplane/api/rest/firewall_handlers.go server/internal/controlplane/api/rest/firewall_portmatch_test.go
git commit -m "fix: keep key padding and parse iptables rules safely"
```

---

### Task 4: fail2ban history, log actions and whitelist (B16)

**Files:**
- Create: `server/internal/controlplane/api/rest/fail2ban_parse.go`, `server/internal/controlplane/api/rest/fail2ban_parse_test.go`
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`handleFail2BanLogs` ~1365-1372, `handleFail2BanGetWhitelist` ~1883-1884, `handleFail2BanHistory` ~2126-2200)
- Modify: `server/internal/controlplane/api/rest/contract_test.go`, `testdata/contract/fail2ban_*.json`

**Interfaces:**
- Produces:
  - `fail2banLogAction(line string) string`;
  - `parseFail2BanHistory(log, jail string, limit int) []map[string]string`;
  - `parseIgnoreIPList(out string) []string`;
  - `var readFail2BanLog func() (string, error)`;
  - `const fail2banLogPath = "/var/log/fail2ban.log"`.

- [ ] **Step 1: Write the failing tests** (`fail2ban_parse_test.go`)

```go
package rest

import (
	"fmt"
	"strings"
	"testing"
)

const sampleF2BLog = `2026-10-13 10:00:01,100 fail2ban.filter  [812]: INFO    [sshd] Found 203.0.113.9 - 2026-10-13 10:00:01
2026-10-13 10:00:05,200 fail2ban.actions [812]: NOTICE  [sshd] Ban 203.0.113.9
2026-10-13 11:00:05,300 fail2ban.actions [812]: NOTICE  [sshd] Unban 203.0.113.9
2026-10-13 11:30:00,400 fail2ban.actions [812]: NOTICE  [recidive] Ban 198.51.100.7
2026-10-13 12:00:00,500 fail2ban.actions [812]: NOTICE  [sshd] Restore Ban 192.0.2.4
`

func TestFail2BanLogAction(t *testing.T) {
	for line, want := range map[string]string{
		"... NOTICE  [sshd] Unban 203.0.113.9":       "unban",
		"... NOTICE  [sshd] Ban 203.0.113.9":         "ban",
		"... NOTICE  [sshd] Restore Ban 192.0.2.4":   "ban",
		"... INFO    [sshd] Found 203.0.113.9 - ...": "found",
		"... INFO    Jail 'sshd' started":            "",
	} {
		if got := fail2banLogAction(line); got != want {
			t.Errorf("fail2banLogAction(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseFail2BanHistory(t *testing.T) {
	all := parseFail2BanHistory(sampleF2BLog, "", 100)
	if len(all) != 4 {
		t.Fatalf("want 4 ban/unban entries, got %d: %v", len(all), all)
	}
	first := all[0] // newest first
	if first["action"] != "ban" || first["jail"] != "sshd" || first["ip"] != "192.0.2.4" || first["timestamp"] != "2026-10-13 12:00:00,500" {
		t.Fatalf("newest entry: %v", first)
	}
	if all[2]["action"] != "unban" || all[2]["jail"] != "sshd" {
		t.Fatalf("unban entry: %v (the jail is the [name], not the [pid])", all[2])
	}
	if got := parseFail2BanHistory(sampleF2BLog, "recidive", 100); len(got) != 1 || got[0]["ip"] != "198.51.100.7" {
		t.Fatalf("jail filter: %v", got)
	}
	if got := parseFail2BanHistory(sampleF2BLog, "sshd", 2); len(got) != 2 || got[0]["ip"] != "192.0.2.4" {
		t.Fatalf("limit keeps the newest: %v", got)
	}
	var big strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&big, "2026-10-13 10:00:00,%03d fail2ban.actions [1]: NOTICE  [sshd] Ban 10.0.%d.%d\n", i%1000, i/250, i%250)
	}
	if got := parseFail2BanHistory(big.String(), "", 3); len(got) != 3 || got[0]["ip"] != "10.0.19.249" {
		t.Fatalf("large log: %d entries, newest %v", len(got), got)
	}
	if got := parseFail2BanHistory("", "", 10); got == nil || len(got) != 0 {
		t.Fatalf("empty log must give an empty, non-nil list: %#v", got)
	}
}

func TestParseIgnoreIPList(t *testing.T) {
	cases := map[string][]string{
		fail2banIgnoreTree: {"127.0.0.0/8", "::1", "10.99.0.0/24"},
		"These IP addresses/networks are ignored:\n|- 192.0.2.0/24\n`- vpn.example.com\n": {"192.0.2.0/24", "vpn.example.com"},
		"No IP address/network is ignored\n":                                              {},
		"127.0.0.1/8 ::1 10.0.0.0/8\n":                                                    {"127.0.0.1/8", "::1", "10.0.0.0/8"},
	}
	for out, want := range cases {
		got := parseIgnoreIPList(out)
		if got == nil || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("parseIgnoreIPList(%q) = %#v, want %v", out, got, want)
		}
	}
}
```

Extend `TestContract`:
- Before the cases, add `readFail2BanLog` to the stubs. In `newContractServer`, save and restore it with the others, and set `readFail2BanLog = func() (string, error) { return "", os.ErrNotExist }` so history is empty by default.
- In `TestContract`, set `readFail2BanLog = func() (string, error) { return sampleF2BLog, nil }` before the loop.
- Add a case `{"fail2ban_history_jail", "GET", "/api/v1/system/fail2ban/ban-history?jail=sshd&limit=2", "", true}` after `fail2ban_history`.

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: a build failure, `undefined: fail2banLogAction` / `parseFail2BanHistory` / `parseIgnoreIPList` / `readFail2BanLog`.

- [ ] **Step 3: Implement** (`fail2ban_parse.go`)

```go
package rest

import (
	"net"
	"os"
	"regexp"
	"strings"
)

const fail2banLogPath = "/var/log/fail2ban.log"

// readFail2BanLog returns the fail2ban log the compose file mounts into the
// container (replaced in tests).
var readFail2BanLog = func() (string, error) {
	b, err := os.ReadFile(fail2banLogPath)
	return string(b), err
}

// f2bActionRe matches "<date> <time>,<ms> fail2ban.actions [pid]: NOTICE  [jail] (Restore )?(Ban|Unban) <ip>".
// The jail is the bracketed name directly before the action, not the [pid].
var f2bActionRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) .*\[([^\]]+)\]\s+(?:Restore )?(Ban|Unban)\s+(\S+)`)

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)

// fail2banLogAction classifies a fail2ban log line ("Unban" contains "Ban",
// so it must be checked first).
func fail2banLogAction(line string) string {
	switch {
	case strings.Contains(line, "Unban"):
		return "unban"
	case strings.Contains(line, "Ban"):
		return "ban"
	case strings.Contains(line, "Found"):
		return "found"
	}
	return ""
}

// parseFail2BanHistory returns the newest limit ban/unban entries, newest
// first, optionally only for one jail. It keeps at most limit entries in
// memory, whatever the log size.
func parseFail2BanHistory(log, jail string, limit int) []map[string]string {
	ring := make([]map[string]string, 0, limit)
	for _, line := range strings.Split(log, "\n") {
		m := f2bActionRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || (jail != "" && m[2] != jail) {
			continue
		}
		entry := map[string]string{"raw": strings.TrimSpace(line), "timestamp": m[1], "jail": m[2],
			"action": strings.ToLower(m[3])}
		if net.ParseIP(m[4]) != nil {
			entry["ip"] = m[4]
		}
		if len(ring) == limit {
			ring = append(ring[1:], entry)
		} else {
			ring = append(ring, entry)
		}
	}
	out := make([]map[string]string, 0, len(ring))
	for i := len(ring) - 1; i >= 0; i-- {
		out = append(out, ring[i])
	}
	return out
}

// parseIgnoreIPList extracts the entries of `fail2ban-client get <jail>
// ignoreip`: the tree format ("|- 127.0.0.0/8", "`- ::1") and the legacy
// single-line list, skipping the header and the "nothing ignored" message.
func parseIgnoreIPList(out string) []string {
	entries := []string{}
	for _, tok := range strings.Fields(out) {
		if net.ParseIP(tok) != nil {
			entries = append(entries, tok)
			continue
		}
		if _, _, err := net.ParseCIDR(tok); err == nil {
			entries = append(entries, tok)
			continue
		}
		if hostnameRe.MatchString(tok) {
			entries = append(entries, tok)
		}
	}
	return entries
}
```

In `handlers.go`:
- **`handleFail2BanLogs`:** replace the `if strings.Contains(line, "Ban") { … } else if … "found" }` block with:

  ```go
  		if action := fail2banLogAction(line); action != "" {
  			logEntry["action"] = action
  		}
  ```

- **`handleFail2BanGetWhitelist`:** replace `ips := strings.Fields(strings.TrimSpace(out))` with `ips := parseIgnoreIPList(out)`.
- **`handleFail2BanHistory`:** keep the `jail`/`limit` parsing. Replace everything from `// Get ban/unban history from fail2ban log` up to the final `jsonResponse` with:

  ```go
  	// The log is read directly; nothing from the request reaches a shell.
  	log, err := readFail2BanLog()
  	if err != nil {
  		log = "" // no log yet: empty history, as before
  	}
  	history := parseFail2BanHistory(log, jail, limit)
  ```

  and keep the `jsonResponse(... "history": history, "count": len(history), "jail": jail ...)` call unchanged. Remove imports that become unused only if the compiler says so.

- [ ] **Step 4: Run them, verify they pass, and update the contract**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: the parser tests pass. `TestContract` fails only on `fail2ban_whitelist`, `fail2ban_history` and the new `fail2ban_history_jail`.

Run: `bash server/scripts/update-contracts.sh`, then `git diff server/internal/controlplane/api/rest/testdata/contract`.
Expected:
- the whitelist lists exactly `127.0.0.0/8`, `::1` and `10.99.0.0/24`;
- history has 4 entries, newest first, with jails `sshd`/`recidive` and actions `ban`/`unban`;
- the jail case has 2 sshd entries;
- no other file changed.

Run the suite again. Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest/fail2ban_parse.go server/internal/controlplane/api/rest/fail2ban_parse_test.go server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/contract_test.go server/internal/controlplane/api/rest/testdata/contract
git commit -m "fix: parse fail2ban history, log actions and whitelist"
```

---

### Task 5: Hub address prefix and no broadcast addresses (B21)

**Files:**
- Modify: `server/internal/controlplane/api/rest/handlers.go:652-655` (`handleCreateNetwork`)
- Create: `server/internal/controlplane/api/rest/network_addr_test.go`
- Modify: `server/internal/controlplane/store/store.go` (`AllocateIP`, ~334-346)
- Create: `server/internal/controlplane/store/allocate_test.go`

**Interfaces:**
- Produces: `hubAddress(cidr string) (string, error)` (rest).

- [ ] **Step 1: Write the failing tests**

`network_addr_test.go`:

```go
package rest

import "testing"

// B21: the hub keeps the network's own prefix, not a hardcoded /24.
func TestHubAddress(t *testing.T) {
	for cidr, want := range map[string]string{
		"10.20.0.0/24":   "10.20.0.1/24",
		"10.20.0.0/16":   "10.20.0.1/16",
		"10.20.5.0/23":   "10.20.4.1/23", // host bits in the input are masked
		"192.168.7.0/28": "192.168.7.1/28",
	} {
		got, err := hubAddress(cidr)
		if err != nil || got != want {
			t.Errorf("hubAddress(%s) = %q, %v; want %s", cidr, got, err, want)
		}
	}
	if _, err := hubAddress("not-a-cidr"); err == nil {
		t.Error("an invalid CIDR must be an error")
	}
}
```

`store/allocate_test.go`:

```go
package store

import (
	"context"
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// B21: allocation skips network, .1 (hub) and .2 as before, and never hands
// out the broadcast address; tiny networks fail cleanly.
func TestAllocateIPNeverReturnsBroadcast(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM networks WHERE name LIKE 'alloc-%'"); err != nil {
		t.Fatal(err)
	}
	n := &models.Network{Name: "alloc-29", CIDR: "10.71.0.0/29", ListenPort: 51971, InterfaceName: "wg171"}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), n.ID) })
	var got []string
	for i := 0; i < 10; i++ {
		ip, err := s.AllocateIP(ctx, n.ID)
		if err != nil {
			break
		}
		got = append(got, ip.String())
		if err := s.CreateNode(ctx, &models.Node{NetworkID: n.ID, Name: "alloc-node-" + ip.String(),
			VirtualIP: ip, PublicKey: strings.Repeat("a", 42) + string(rune('A'+i)) + "=", Labels: map[string]string{}}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(got, ",") != "10.71.0.3,10.71.0.4,10.71.0.5,10.71.0.6" {
		t.Fatalf("/29 allocated %v, want .3-.6 (never .7, the broadcast)", got)
	}
	for _, cidr := range []string{"10.72.0.0/30", "10.73.0.0/31", "10.74.0.0/32"} {
		tiny := &models.Network{Name: "alloc-" + cidr, CIDR: cidr, ListenPort: 51972, InterfaceName: "wg172"}
		if err := s.CreateNetwork(ctx, tiny); err != nil {
			t.Fatal(err)
		}
		if ip, err := s.AllocateIP(ctx, tiny.ID); err == nil {
			t.Errorf("%s: allocated %v, want an error", cidr, ip)
		}
		s.DeleteNetwork(ctx, tiny.ID)
	}
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected:
- `api/rest` fails to build with `undefined: hubAddress`;
- in the same run, the `store` package (which builds on its own) fails `TestAllocateIPNeverReturnsBroadcast` with `/29 allocated [10.71.0.3 10.71.0.4 10.71.0.5 10.71.0.6 10.71.0.7]` (the broadcast is handed out).

- [ ] **Step 3: Implement**

In `handlers.go` (add `"net/netip"` to the imports):

```go
// hubAddress returns the hub's interface address for a network: the first
// host of cidr, with cidr's own prefix length (B21: not a fixed /24).
func hubAddress(cidr string) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	p = p.Masked()
	return netip.PrefixFrom(p.Addr().Next(), p.Bits()).String(), nil
}
```

In `handleCreateNetwork`, replace the four lines from `_, ipNet, _ := net.ParseCIDR(network.CIDR)` to `serverAddr := fmt.Sprintf("%s/24", serverIP.String())`, and the `if err := mgr.CreateServerConfigWithKey(privateKey, serverAddr, port); err != nil {` line that follows them, with:

```go
		serverAddr, addrErr := hubAddress(network.CIDR)
		if addrErr != nil {
			fmt.Printf("Warning: invalid CIDR %s: %v\n", network.CIDR, addrErr)
		} else if err := mgr.CreateServerConfigWithKey(privateKey, serverAddr, port); err != nil {
```

The existing body of that `if` (the `Failed to create WireGuard config` print) and its `} else { … }` branch stay as they are. `net` stays imported (`networksOverlap` and `net.ParseCIDR` validation use it).

In `store.go` `AllocateIP`, after `ip := ipNet.IP.Mask(ipNet.Mask)` add:

```go
	// The broadcast address (all host bits set) is never a valid peer.
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^ipNet.Mask[i]
	}
```

Change the loop header `for ipNet.Contains(ip) {` to `for ipNet.Contains(ip) && !ip.Equal(broadcast) {`. Fix the misleading comment to: `// Find the next free IP: skip network, .1 (hub) and .2 as before; never the broadcast`.

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`. `TestContract` is unchanged: `network_create` returns the same body, because the address is only in `wgN.conf`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/network_addr_test.go server/internal/controlplane/store/store.go server/internal/controlplane/store/allocate_test.go
git commit -m "fix: use the network prefix for the hub and skip broadcast"
```

---

### Task 6: Never log the database password

**Files:**
- Modify: `server/cmd/control-plane/main.go` (`maskDatabaseURL`, ~371-375)
- Create: `server/cmd/control-plane/main_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"strings"
	"testing"
)

func TestMaskDatabaseURLHidesPassword(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://novus:s3cr3t@postgres:5432/novusgate?sslmode=disable": "postgres://novus:xxxxx@postgres:5432/novusgate?sslmode=disable",
		"host=postgres user=novus password=s3cr3t dbname=novusgate":        "host=postgres user=novus password=xxxxx dbname=novusgate",
		"postgres://postgres:5432/novusgate":                              "postgres://postgres:5432/novusgate",
	} {
		got := maskDatabaseURL(in)
		if got != want || strings.Contains(got, "s3cr3t") {
			t.Errorf("maskDatabaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `FAIL: TestMaskDatabaseURLHidesPassword` (today the URL is returned unchanged).

- [ ] **Step 3: Implement**

Add `"net/url"` and `"regexp"` to the main.go imports if they are missing.

```go
var dsnPasswordRe = regexp.MustCompile(`(password=)\S+`)

// maskDatabaseURL hides the password in a postgres URL or key=value DSN so
// it never reaches the logs.
func maskDatabaseURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.User != nil {
		return u.Redacted()
	}
	return dsnPasswordRe.ReplaceAllString(raw, "${1}xxxxx")
}
```

(Go's `url.URL.Redacted` replaces the password with `xxxxx`.)

- [ ] **Step 4: Run it and verify it passes**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `ok …/cmd/control-plane` and all others `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/cmd/control-plane/main.go server/cmd/control-plane/main_test.go
git commit -m "security: mask the database password in startup logs"
```

---

### Task 7: Frontend reads both error body forms

P2d will switch errors to `{"error":{"code","message"}}`. Today 5 places read `data.error` as a string, and they would show `[object Object]` after that switch.

**Files:**
- Create: `web/src/api/errors.ts`
- Modify: `web/src/App.tsx:43`, `web/src/pages/Settings/ChangePasswordCard.tsx:43`, `web/src/pages/Settings/UserManagementCard.tsx:24`, `web/src/pages/Networks/Networks.tsx:35`, `web/src/pages/Firewall/Firewall.tsx:143`

**Interfaces:**
- Produces: `errorBodyMessage(data: unknown): string | undefined` and `apiErrorMessage(err: unknown, fallback: string): string`.

- [ ] **Step 1: Ledger the TDD exception**

`web/` has no test runner, and adding one is a new package (Global Constraints). Write this ledger line: `Task 7: Ruling: no JS test runner — helper verified by tsc --noEmit and by reading each call site — cost if wrong: a wrong message text in 5 places, no crash`.

- [ ] **Step 2: Implement `web/src/api/errors.ts`**

```ts
// Error bodies are {"error":"message"} today and {"error":{"code","message"}}
// after the unified error format (P2d); read both.
export function errorBodyMessage(data: unknown): string | undefined {
  if (!data || typeof data !== 'object') return undefined
  const error = (data as { error?: unknown }).error
  if (typeof error === 'string') return error
  if (error && typeof error === 'object') {
    const message = (error as { message?: unknown }).message
    if (typeof message === 'string') return message
  }
  return undefined
}

// apiErrorMessage returns the server's message for an axios error, else the
// error's own message, else fallback.
export function apiErrorMessage(err: unknown, fallback: string): string {
  const response = (err as { response?: { data?: unknown } } | undefined)?.response
  return (
    errorBodyMessage(response?.data) ??
    (err instanceof Error && err.message ? err.message : undefined) ??
    fallback
  )
}
```

Replace the call sites:

| File | Old | New |
|---|---|---|
| `App.tsx:43` | `throw new Error(data.error \|\| 'Login failed')` | `throw new Error(errorBodyMessage(data) ?? 'Login failed')` |
| `ChangePasswordCard.tsx:43` | `setError(err.response?.data?.error \|\| 'Failed to update password')` | `setError(apiErrorMessage(err, 'Failed to update password'))` |
| `UserManagementCard.tsx:24` | (same pattern) | `setError(apiErrorMessage(err, 'Failed to create user'))` |
| `Networks.tsx:35` | `const message = error?.response?.data?.error \|\| error?.message \|\| 'Failed to create network'` | `const message = apiErrorMessage(error, 'Failed to create network')` |
| `Firewall.tsx:143` | `const errorMessage = error?.response?.data?.error \|\| error?.message \|\| 'Unknown error'` | `const errorMessage = apiErrorMessage(error, 'Unknown error')` |

Add `import { apiErrorMessage } from '…/api/errors'` (or `errorBodyMessage` for App.tsx) with the right relative path in each file.

Note on the Networks and Firewall rows: the old code fell back to the raw axios `error.message` ("Request failed with status code 409") only when the body had no `error`. The new helper behaves the same.

- [ ] **Step 3: Verify**

Write the scratchpad script `tsc.sh`. It copies `web/` (without `node_modules` and `dist`) into the container, runs `npm ci --silent`, then `npx tsc --noEmit` and `npx biome check src/api/errors.ts`. Run it with `MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/web:/w:ro -v <scratchpad>:/s node:20-bookworm sh /s/tsc.sh`.
Expected: `tsc exit=0`, and biome reports no errors for the new file. If biome is not installed in `devDependencies`, record that and rely on tsc.

Run: `grep -rn "data?.error\|data.error" web/src --include=*.tsx --include=*.ts`.
Expected: only `web/src/api/errors.ts`, plus `Fail2BanLogs.error` (a success-body field, untouched).

- [ ] **Step 4: Commit**

```bash
git add web/src/api/errors.ts web/src/App.tsx web/src/pages/Settings/ChangePasswordCard.tsx web/src/pages/Settings/UserManagementCard.tsx web/src/pages/Networks/Networks.tsx web/src/pages/Firewall/Firewall.tsx
git commit -m "feat: read both legacy and unified API error bodies"
```

---

### Task 8: Documentation

**Files:**
- Modify: `docs/api.md`, `docs/architecture.md`, `docs/active-context.md`, `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` (§7: mark B14, B16, B21, B22 with commit hashes)

- [ ] **Step 1: Write**
  - **`docs/api.md`.** Add a "Kontrakt testləri" section:
    - snapshots are in `server/internal/controlplane/api/rest/testdata/contract/`;
    - update them with `bash server/scripts/update-contracts.sh`;
    - every diff is an API change.

    Add a "P2a-da dəyişən cavablar" section covering the empty lists, fail2ban history/whitelist and logs action, matching spec §3.
  - **`docs/architecture.md`.** Add a "Test seam-ləri" bullet listing `execHostCommand`, `execCommand`, `generateKeys`, `readFail2BanLog`, `legacySSHPorts` and the firewall seams. Also note that the hub address follows the CIDR prefix.
  - **`docs/active-context.md`.** Add a session block and table rows.
  - **Master spec §7.** B14, B16, B21, B22 → "P2a-da bağlandı (`<hash>`)".

- [ ] **Step 2: Verify**

Run: `bash server/scripts/test-with-postgres.sh`.
Expected: all `ok` (docs only; this confirms the branch is green).

- [ ] **Step 3: Commit**

```bash
git add docs/api.md docs/architecture.md docs/active-context.md docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md
git commit -m "docs: document P2a contract tests and bug fixes"
```

---

## Out of scope (next P2 plans)
- **P2b:** slog, request log, recover middleware, `/health`, the double middleware.
- **P2c:** the `netctl/wg` interface, the reconciler, the expiry job (B11), the `loadNetworks` adopt flow, and the `handleCreateNetwork` double `Up`.
- **P2d:** the service layer, the unified error format on the server, OpenAPI.
- **P4:** auth on `install.sh` and check-in; the install script's `architecture` vs `arch` field.
