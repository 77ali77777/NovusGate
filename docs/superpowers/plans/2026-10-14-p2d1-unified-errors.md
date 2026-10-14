# P2d-1 Unified Error Format and Node Input Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- Every API error body becomes `{"error":{"code":"<snake_case>","message":"..."}}`, and the errors a client acts on get stable codes.
- `PUT /nodes/{id}` rejects an unknown `status` and an unparsable `expires_at` instead of silently storing or ignoring them.

**Architecture:**
- `errorResponse(w, status, message)` keeps its signature (167 call sites) and derives a default code from the HTTP status.
- A new `errorWithCode(w, status, code, message)` serves the call sites that need a specific code: credentials, CIDR overlap, admin network, protected rules, firewall engine states, invalid body.
- The web already reads both bodies (`web/src/api/errors.ts`, P2a), so web and server deploy together safely.

**Tech Stack:** Go 1.23, gorilla/mux, PostgreSQL 16 (tests).

**Spec:**
- `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md` §1 (P2d row) and §2.3 (two-step error switch: the web reads both first in P2a, the server switches in P2d).
- Master spec `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` §4.1: "Vahid xəta formatı: `{"error":{"code":"<snake_case>","message":"..."}}`. Köhnə `{"error":"..."}` forması P2-də deprecate olunur. Frontend hər iki formanı oxuyur."

## Global Constraints

- **The only API contract change allowed here is the error body shape**, plus the two new 400s on `PUT /nodes/{id}`. HTTP status codes and success bodies stay exactly as they are. Every change is a contract-snapshot diff in the same commit.
- **`message` keeps today's text verbatim**, so UIs and logs that show the message are unchanged.
- **Codes are `snake_case` and stable.** Once released, a code is never renamed.
- **Error-like fields inside 200 bodies are untouched.** These are fail2ban `error`, `/health`, `host_error` and sync `errors`; only `errorResponse` output changes.
- **No new Go modules or npm packages.**
- **Environment:** Go runs only in Docker (`bash server/scripts/test-with-postgres.sh`). Snapshots are updated with `bash server/scripts/update-contracts.sh`. The WSL shim expands `$`/`|`, so logic goes in script files.
- Commits carry no `Co-Authored-By`/"Claude"/"Anthropic"/"AI generated" lines. Comments in English, docs in Azerbaijani with full diacritics.

## Review Focus

1. **An old web build cached in a browser receives the new body.**
   - The current web reads both forms (P2a `errors.ts`).
   - Expected: no `[object Object]` anywhere. A grep in Task 4 proves no other web code reads `data.error` as a string.
2. **A 401 from the auth middleware** (missing or invalid token, API key).
   - Expected: the same status and the new body. The axios interceptor redirects on status only (`client.ts:46-55`), so login flows are unaffected.
   - Pinned by the `unauthorized` contract snapshot.
3. **A panic → 500 from `RecoverMiddleware`.**
   - Expected: `{"error":{"code":"internal_error","message":"internal server error"}}`.
   - Pinned by `TestRecoverMiddleware`.
4. **`PUT /nodes/{id}` from the current web:**
   - `status` comes from the select (`pending|online|offline|expired`);
   - `expires_at` comes from `Date.toISOString()` (RFC 3339 with milliseconds).
   - Expected: still accepted.
   - Pinned by Task 3 `TestUpdateNodeValidatesInput` (accepts `2026-10-14T12:00:00.000Z`).
5. **Center's server registration** (`NovusGate Center/server.js:815-831`).
   - It only reads `response.config` and never the error body.
   - Expected: unaffected. Recorded in docs; no test, as Center is outside the Go suite.

---

### Task 1: The unified error body

**Files:**
- Modify: `server/internal/controlplane/api/rest/handlers.go:390-392` (`errorResponse`)
- Create: `server/internal/controlplane/api/rest/errors_test.go`
- Modify: `server/internal/controlplane/api/rest/middleware_test.go:55`
- Modify: `server/internal/controlplane/api/rest/testdata/contract/*.json` (regenerated)

**Interfaces:**
- Produces:
  - `errorWithCode(w http.ResponseWriter, status int, code, message string)`;
  - `defaultErrorCode(status int) string`;
  - `errorResponse` keeps its signature.

- [ ] **Step 1: Write the failing test** (`errors_test.go`)

```go
package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorBodyIsUnified(t *testing.T) {
	cases := map[int]string{
		400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
		405: "method_not_allowed", 409: "conflict", 410: "gone", 500: "internal_error",
		502: "bad_gateway", 503: "unavailable", 418: "error",
	}
	for status, code := range cases {
		rec := httptest.NewRecorder()
		errorResponse(rec, status, "something <went> wrong")
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%d: body %q is not the unified shape: %v", status, rec.Body, err)
		}
		if rec.Code != status || body.Error.Code != code || body.Error.Message != "something <went> wrong" {
			t.Errorf("%d: got status %d, code %q, message %q", status, rec.Code, body.Error.Code, body.Error.Message)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%d: content type %q", status, rec.Header().Get("Content-Type"))
		}
	}
	rec := httptest.NewRecorder()
	errorWithCode(rec, http.StatusConflict, "cidr_overlap", "overlaps")
	if rec.Code != 409 || rec.Body.String() != `{"error":{"code":"cidr_overlap","message":"overlaps"}}`+"\n" {
		t.Fatalf("errorWithCode = %d %q", rec.Code, rec.Body)
	}
}
```

In `middleware_test.go:55`, change the expected body to `{"error":{"code":"internal_error","message":"internal server error"}}`.

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: a build failure, `undefined: errorWithCode`.

- [ ] **Step 3: Implement** (`handlers.go`, replace `errorResponse`)

```go
// apiError is the unified error body: {"error":{"code","message"}}. The code
// is stable snake_case for clients to act on; the message is for people.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errorWithCode writes an error with a specific code.
func errorWithCode(w http.ResponseWriter, status int, code, message string) {
	jsonResponse(w, status, map[string]apiError{"error": {Code: code, Message: message}})
}

// errorResponse writes an error whose code follows the HTTP status.
func errorResponse(w http.ResponseWriter, status int, message string) {
	errorWithCode(w, status, defaultErrorCode(status), message)
}

// defaultErrorCode names an HTTP status as a stable error code.
func defaultErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusConflict:
		return "conflict"
	case http.StatusGone:
		return "gone"
	case http.StatusInternalServerError:
		return "internal_error"
	case http.StatusBadGateway:
		return "bad_gateway"
	case http.StatusServiceUnavailable:
		return "unavailable"
	}
	return "error"
}
```

The test expects `<` unescaped in the message. `jsonResponse` uses `json.NewEncoder`, which escapes HTML by default, so `<` becomes `<` on the wire. After `json.Unmarshal` the message reads back as `<went>`, so the test above holds. Do not change `jsonResponse`.

- [ ] **Step 4: Run them, verify they pass, and update the contract**

Run: `bash server/scripts/test-with-postgres.sh`
Expected:
- `TestErrorBodyIsUnified` and `TestRecoverMiddleware` pass;
- `TestContract` fails exactly on the error cases: `unauthorized`, `login_bad`, `network_get_missing`, `network_create_overlap` and `network_create_bad_body`.

Run: `bash server/scripts/update-contracts.sh`, then `git diff --stat server/internal/controlplane/api/rest/testdata/contract`.
Expected: exactly those 5 files changed. Each body becomes `{"error":{"code":<default>,"message":<same text>}}`, and no success snapshot changed.

Run the suite again. Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/errors_test.go server/internal/controlplane/api/rest/middleware_test.go server/internal/controlplane/api/rest/testdata/contract
git commit -m "feat: return errors as {error:{code,message}}"
```

---

### Task 2: Specific codes where clients act on them

**Files:**
- Modify: `server/internal/controlplane/api/rest/handlers.go` (login :424/:429, password :460/:465, overlap ~:590, admin network :706)
- Modify: `server/internal/controlplane/api/rest/firewall_handlers.go` (:422, :426, :721)
- Modify: `server/internal/controlplane/api/rest/firewall_v1_nft.go` (:167, :239)
- Modify: `server/internal/controlplane/api/rest/firewall_engine.go` (`engineError`)
- Modify: every `errorResponse(w, http.StatusBadRequest, "invalid request body")` (24 sites, `grep -rn`)
- Create: `server/internal/controlplane/api/rest/error_codes_test.go`

**Interfaces:**
- Consumes: `errorWithCode` (Task 1), `newContractServer`, `seedContract`, `callAs`, `newEngineServer`, `call`.

Codes:

| Code | Status | Where |
|---|---|---|
| `invalid_request_body` | 400 | every undecodable JSON body |
| `invalid_credentials` | 401 | login (both "invalid credentials" sites), password update when the user is unknown |
| `invalid_old_password` | 401 | password update, wrong old password (status stays 401; B15 changes it in P4) |
| `cidr_overlap` | 409 | network create |
| `admin_network_protected` | 403 | delete wg0 |
| `protected_rule` | 403 | Close Port (protected port / SSH port), Delete rule (protected) in iptables and nft mode |
| `firewall_disabled` | 409 | `firewall.ErrEngineDisabled` |
| `firewall_not_ready` | 409 | `firewall.ErrNotReady` |
| `firewall_change_pending` | 409 | `nft.ErrPendingConfirmation` |
| `firewall_rollback_armed` | 409 | `nft.ErrRollbackArmed` |
| `conflict` | 409 | `errConflict` (duplicate forward) |
| `firewall_rejected` | 400 | `firewall.ErrRejected` (lockout guard, reserved port, allow inside block) |
| `firewall_change_expired` | 410 | `nft.ErrExpired`, `nft.ErrNoPending` |
| `not_found` | 404 | `errNotFound` |
| `internal_error` | 500 | other engine errors |

- [ ] **Step 1: Write the failing test** (`error_codes_test.go`)

```go
package rest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var b struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("not an error body: %s", body)
	}
	return b.Error.Code
}

func TestErrorCodes(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	admin := &models.Network{Name: "contract-admin", CIDR: "10.98.0.0/24", ListenPort: 51898, InterfaceName: "wg0"}
	if err := st.CreateNetwork(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"bad body", "POST", "/api/v1/networks", `{`, 400, "invalid_request_body"},
		{"login", "POST", "/api/v1/auth/login", `{"username":"contract-user","password":"nope"}`, 401, "invalid_credentials"},
		{"login unknown", "POST", "/api/v1/auth/login", `{"username":"ghost","password":"nope"}`, 401, "invalid_credentials"},
		{"old password", "PUT", "/api/v1/auth/password", `{"username":"contract-user","oldPassword":"nope","newPassword":"x1y2z3"}`, 401, "invalid_old_password"},
		{"overlap", "POST", "/api/v1/networks", `{"name":"contract-o","cidr":"10.66.0.0/25"}`, 409, "cidr_overlap"},
		{"admin network", "DELETE", "/api/v1/networks/" + admin.ID, "", 403, "admin_network_protected"},
		{"protected port", "POST", "/api/v1/firewall/host/port/close", `{"port":22,"protocol":"tcp"}`, 403, "protected_rule"},
		{"missing", "GET", "/api/v1/networks/00000000-0000-4000-8000-000000000000", "", 404, "not_found"},
	}
	for _, c := range cases {
		rec := callAs(t, s, c.method, c.path, c.body, true)
		if rec.Code != c.status || errorCode(t, rec.Body.Bytes()) != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, rec.Code, rec.Body, c.status, c.code)
		}
	}
}

func TestFirewallEngineErrorCodes(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeShadow)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`); rec.Code != 409 || errorCode(t, rec.Body.Bytes()) != "firewall_disabled" {
		t.Fatalf("shadow mode v2 change = %d %s", rec.Code, rec.Body)
	}
	s, _ = newEngineServer(t, firewall.ModeNft)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`); rec.Code != 200 {
		t.Fatalf("pending change = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9444}`); rec.Code != 409 || errorCode(t, rec.Body.Bytes()) != "firewall_change_pending" {
		t.Fatalf("second change while one is pending = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/confirm/no-such-id", ""); rec.Code != 410 || errorCode(t, rec.Body.Bytes()) != "firewall_change_expired" {
		t.Fatalf("confirm of an unknown change = %d %s", rec.Code, rec.Body)
	}

	// The lockout guard: a fresh engine (nothing pending) refuses to block the operator.
	s, _ = newEngineServer(t, firewall.ModeNft)
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", `{"ip":"198.51.100.200"}`); rec.Code != 400 || errorCode(t, rec.Body.Bytes()) != "firewall_rejected" {
		t.Fatalf("blocking the operator = %d %s", rec.Code, rec.Body)
	}
}
```

The password request uses the JSON fields `username`, `oldPassword` and `newPassword` (`handleUpdatePassword`). `nft.SafeApplier.Confirm` returns `ErrNoPending` for an unknown id. `call` sets `RemoteAddr` 198.51.100.200, the operator the lockout guard protects, and v1 Block IP applies with `confirm=false`.

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `FAIL: TestErrorCodes` and `TestFirewallEngineErrorCodes`, showing default codes (`bad_request`, `unauthorized`, `conflict`, `forbidden`, `gone`) where specific ones are wanted.

- [ ] **Step 3: Implement**

Bad bodies, mechanically:

```bash
grep -rln 'errorResponse(w, http.StatusBadRequest, "invalid request body")' server/internal/controlplane/api/rest --include=*.go
```

In each listed non-test file, replace that exact call with `errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")`. Use a script file in the scratchpad running `sed -i` with a fixed-string pattern, then repeat the `grep`. Expected: no output.

Then replace the specific sites. The message text stays the same:
- login: both `errorResponse(w, http.StatusUnauthorized, "invalid credentials")` in `handleLogin` → `errorWithCode(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")`;
- `handleUpdatePassword`: its `"invalid credentials"` → `invalid_credentials`, and `"invalid old password"` → `errorWithCode(w, http.StatusUnauthorized, "invalid_old_password", "invalid old password")`;
- `handleCreateNetwork` overlap: `errorResponse(w, http.StatusConflict, fmt.Sprintf(…))` → `errorWithCode(w, http.StatusConflict, "cidr_overlap", fmt.Sprintf(…))`;
- `handleDeleteNetwork`: `"cannot delete Admin Management Network"` → `errorWithCode(w, http.StatusForbidden, "admin_network_protected", "cannot delete Admin Management Network")`;
- `firewall_handlers.go` :422, :426, :721 and `firewall_v1_nft.go` :167, :239: `errorResponse(w, http.StatusForbidden, X)` → `errorWithCode(w, http.StatusForbidden, "protected_rule", X)`.

`engineError` (`firewall_engine.go`): replace it with:

```go
// engineError writes the HTTP status and stable code that match an engine error.
func engineError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "internal_error"
	switch {
	case errors.Is(err, errNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, firewall.ErrEngineDisabled):
		status, code = http.StatusConflict, "firewall_disabled"
	case errors.Is(err, firewall.ErrNotReady):
		status, code = http.StatusConflict, "firewall_not_ready"
	case errors.Is(err, errConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, nft.ErrPendingConfirmation):
		status, code = http.StatusConflict, "firewall_change_pending"
	case errors.Is(err, nft.ErrRollbackArmed):
		status, code = http.StatusConflict, "firewall_rollback_armed"
	case errors.Is(err, firewall.ErrRejected):
		status, code = http.StatusBadRequest, "firewall_rejected"
	case errors.Is(err, nft.ErrExpired), errors.Is(err, nft.ErrNoPending):
		status, code = http.StatusGone, "firewall_change_expired"
	}
	errorWithCode(w, status, code, err.Error())
}
```

- [ ] **Step 4: Run them, verify they pass, and update the contract**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: both new tests pass. `TestContract` fails only on `login_bad` (`invalid_credentials`), `network_create_overlap` (`cidr_overlap`) and `network_create_bad_body` (`invalid_request_body`).

Run: `bash server/scripts/update-contracts.sh`, then `git diff --stat …/testdata/contract`.
Expected: exactly those 3 files changed, with only the `code` value differing.

Run the suite again. Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest
git commit -m "feat: add stable error codes for actionable API errors"
```

---

### Task 3: Validate `PUT /nodes/{id}` input

Today an unknown `status` (e.g. `"banana"`) is stored as is, and an unparsable `expires_at` is silently ignored, so the user's change is lost without a word.

**Files:**
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`handleUpdateNode`, the `expires_at` and status blocks)
- Create: `server/internal/controlplane/api/rest/node_update_test.go`
- Modify: `server/internal/controlplane/api/rest/contract_test.go` (two new cases)

**Interfaces:**
- Consumes: `errorWithCode`.

- [ ] **Step 1: Write the failing test** (`node_update_test.go`)

```go
package rest

import "testing"

func TestUpdateNodeValidatesInput(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	path := "/api/v1/nodes/" + seed.node.ID
	for body, code := range map[string]string{
		`{"status":"banana"}`:            "invalid_status",
		`{"expires_at":"next tuesday"}`: "invalid_expires_at",
	} {
		rec := callAs(t, s, "PUT", path, body, true)
		if rec.Code != 400 || errorCode(t, rec.Body.Bytes()) != code {
			t.Errorf("%s = %d %s, want 400 %s", body, rec.Code, rec.Body, code)
		}
	}
	// What the web sends today must keep working.
	for _, body := range []string{
		`{"status":"offline"}`,
		`{"expires_at":"2099-10-14T12:00:00.000Z"}`, // Date.toISOString()
		`{"expires_at":""}`,                          // remove the expiry
		`{"name":"contract-node-x"}`,
	} {
		if rec := callAs(t, s, "PUT", path, body, true); rec.Code != 200 {
			t.Errorf("%s = %d %s, want 200", body, rec.Code, rec.Body)
		}
	}
	n, _ := st.GetNode(t.Context(), seed.node.ID)
	if n.Status != "offline" {
		t.Fatalf("a rejected update must not be stored; status = %s", n.Status)
	}
}
```

`t.Context()` needs Go 1.24. If the build reports `t.Context undefined` (the project is on Go 1.23), use `context.Background()` and import `context`. That is a test-only adjustment; ledger it.

Add two contract cases to `TestContract`, before `node_update`:

```go
		{"node_update_bad_status", "PUT", "/api/v1/nodes/" + node, `{"status":"banana"}`, true},
		{"node_update_bad_expiry", "PUT", "/api/v1/nodes/" + node, `{"expires_at":"next tuesday"}`, true},
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected:
- `FAIL: TestUpdateNodeValidatesInput`: `{"status":"banana"} = 200 …` and `{"expires_at":"next tuesday"} = 200 …`;
- `TestContract`: the two new snapshots are missing.

- [ ] **Step 3: Implement** (`handleUpdateNode`)

Replace the `expires_at` block with:

```go
	// Update expires_at
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			// Empty string means remove expiration
			node.ExpiresAt = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				errorWithCode(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be an RFC 3339 time, e.g. 2026-10-14T12:00:00Z")
				return
			}
			node.ExpiresAt = &t
		}
	}
```

Replace the status block's first branch with:

```go
	if req.Status != nil {
		switch st := models.NodeStatus(*req.Status); st {
		case models.NodeStatusPending, models.NodeStatusOnline, models.NodeStatusOffline, models.NodeStatusExpired:
			node.Status = st
		default:
			errorWithCode(w, http.StatusBadRequest, "invalid_status", "status must be pending, online, offline or expired")
			return
		}
	} else if node.Status == models.NodeStatusExpired && req.ExpiresAt != nil && *req.ExpiresAt != "" {
```

Keep the rest of that `else if` branch as it is. Both checks run before `s.store.UpdateNode`, so nothing is stored for a rejected request.

- [ ] **Step 4: Run them, verify they pass, and record the snapshots**

Run: `bash server/scripts/update-contracts.sh`, then `git status --short …/testdata/contract`.
Expected: two new files, `node_update_bad_status.json` and `node_update_bad_expiry.json`, each 400 with its code. No other file changed.

Run: `bash server/scripts/test-with-postgres.sh`. Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest
git commit -m "fix: reject unknown node status and unparsable expires_at"
```

---

### Task 4: Documentation and web check

**Files:**
- Modify: `docs/api.md` (an error format section with the code table), `docs/architecture.md` (one line), `docs/active-context.md`
- Modify: `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md` (P2d split: P2d-1 done; P2d-2 OpenAPI, P2d-3 service layer)

- [ ] **Step 1: Verify the web reads only through the helper**

Run: `grep -rn "data?.error\|data\.error\|response?.data?.error" web/src --include=*.ts --include=*.tsx`
Expected: no match outside `web/src/api/errors.ts`. The `Fail2BanLogs.error` type field is a success body. If anything else matches, switch it to `apiErrorMessage` in this task.

- [ ] **Step 2: Write**
  - **`docs/api.md`, a "Xəta formatı (P2d-1)" section:**
    - the body `{"error":{"code","message"}}`;
    - the default code per status;
    - the specific code table from Task 2, plus `invalid_status` and `invalid_expires_at`;
    - "Köhnə `{"error":"..."}` forması artıq qaytarılmır; web hər ikisini oxuyur (`web/src/api/errors.ts`)";
    - Center reads only `config` from server registration.
  - **`docs/architecture.md`:** one bullet: `errorResponse`/`errorWithCode`, code stability.
  - **P2 spec:** split P2d into P2d-1 (done), P2d-2 (OpenAPI from the contract snapshots + route coverage test) and P2d-3 (service layer).
  - **`docs/active-context.md`:** a session block plus a table row.

- [ ] **Step 3: Verify**

Run: `bash server/scripts/test-with-postgres.sh`. Expected: all `ok`.

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "docs: document the unified error format and codes"
```

---

## Out of scope
- **P2d-2:** the OpenAPI document and the route coverage test.
- **P2d-3:** the service layer (handler → service → store).
- **B15** (wrong old password logs the user out): the status change to 400 is P4.
- **500 messages that carry internal error text** (engine errors): message hygiene is P4 (auth/install hardening).
