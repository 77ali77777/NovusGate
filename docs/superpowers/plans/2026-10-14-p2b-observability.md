# P2b Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the control plane observable. That means structured `log/slog` output (JSON by default), one real log line per HTTP request, a panic never dropping a connection silently, and a `/health` that checks the database, WireGuard interfaces and the firewall engine.

**Architecture:**
- A tiny `internal/shared/logging` package builds the process logger from `LOG_FORMAT`/`LOG_LEVEL`. `slog.SetDefault` also routes the standard `log` package through it.
- The REST router gets `LoggingMiddleware` (a status-recording writer) and `RecoverMiddleware`. The second, duplicate middleware wrap in `main.go` is removed.
- `/health` keeps its two fields and **adds** a `checks` object.
- Every runtime `fmt.Print*`/`log.Print*` becomes `slog`. A source-scanning test keeps it that way.

**Tech Stack:** Go 1.23 standard library (`log/slog`, `go/parser`), gorilla/mux, PostgreSQL 16 (tests).

**Spec:** `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md` §1 (P2b row), which elaborates master spec `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` §4.1 ("Log: `log/slog`, JSON… request log middleware", "Health: DB, interfaces, reconciler, nft ruleset").

## Global Constraints

- **No new Go modules.** `log/slog` and `go/parser` are standard library.
- **API contract (master spec §3.1):** `/health` keeps `status` and `version`, and only adds fields. HTTP status stays **200** (there are no automated consumers today; a 503 would change the contract).
- **Log messages keep their current text.** The runbooks grep for lines such as `iptables INPUT handed over to nftables`, `imported N panel rules` and `host not ready for FIREWALL_ENGINE=nft`. JSON output keeps them inside `"msg"`.
- **What is never logged:** query strings, headers, request bodies, tokens and passwords.
- **CLI commands keep plain `fmt` output for the user:** `migrate`, `init`, `version`, `firewall preview`. Only the server runtime logs through `slog`.
- The reconciler health check belongs to P2c (the reconciler does not exist yet).
- **Environment:**
  - Go runs only in Docker: `bash server/scripts/test-with-postgres.sh`.
  - Contract snapshots: `bash server/scripts/update-contracts.sh`.
  - The WSL docker shim expands `$`/`|` in arguments, so logic goes in script files.
  - No `--privileged`.
- Commits carry no `Co-Authored-By`/"Claude"/"Anthropic"/"AI generated" lines. Comments in English, docs in Azerbaijani with full diacritics.

## Review Focus

1. **Secrets in request logs.**
   - Expected: an `Authorization: Bearer …` header, `?token=` or `?password=` query, or a login body never appears in any log line.
   - Pinned by Task 2 `TestRequestLogNeverContainsSecrets`.
2. **Panic after a partial write, or `http.ErrAbortHandler`.**
   - Expected: the process survives; `ErrAbortHandler` is re-panicked as net/http expects; other panics are logged with their stack.
   - Pinned by Task 2 `TestRecoverMiddleware`.
3. **Database down.**
   - Expected: `/health` still answers 200 within ~2 s with `status: degraded` and `database.ok: false`, never hangs or 500s.
   - Pinned by Task 3 `TestHealthWhenDatabaseIsDown`.
4. **Invalid `LOG_FORMAT`/`LOG_LEVEL`.**
   - Expected: the server still starts (JSON/info) and warns once. A typo in a logging variable must not take the VPN control plane down.
   - Pinned by Task 1 `TestNewRejectsUnknownValues` and the `main.go` fallback step.
5. **A new `fmt.Printf` added later in runtime code.**
   - Expected: CI fails with file:line.
   - Pinned by Task 4 `TestRuntimeCodeLogsThroughSlog`.

---

## File Structure

| File | Responsibility |
|---|---|
| `server/internal/shared/logging/logging.go` (create) | `New(w, format, level)` |
| `server/internal/shared/logging/logging_test.go` (create) | logger tests |
| `server/internal/shared/logging/noprint_test.go` (create) | source scan: runtime code logs through slog |
| `server/internal/controlplane/api/rest/middleware.go` (create) | `LoggingMiddleware`, `RecoverMiddleware`, `statusRecorder` |
| `server/internal/controlplane/api/rest/middleware_test.go` (create) | middleware tests |
| `server/internal/controlplane/api/rest/handlers.go` (modify) | router middleware order; remove the old no-op `LoggingMiddleware`; `handleHealth`; prints → slog |
| `server/internal/controlplane/api/rest/health_test.go` (create) | health tests |
| `server/internal/controlplane/store/store.go` (modify) | `Ping` |
| `server/internal/controlplane/firewall/engine.go` (modify) | `Ready()`; `log` → slog |
| `server/cmd/control-plane/main.go` (modify) | logger setup; single middleware wrap; runtime prints → slog |
| `server/deployments/docker/docker-compose.yml` (modify) | `LOG_FORMAT`, `LOG_LEVEL` |
| other runtime files with prints (Task 4 list) | prints → slog |
| `docs/*` | docs |

---

### Task 1: The process logger

**Files:**
- Create: `server/internal/shared/logging/logging.go`, `server/internal/shared/logging/logging_test.go`
- Modify: `server/cmd/control-plane/main.go` (start of `runServer`, ~129)
- Modify: `server/deployments/docker/docker-compose.yml` (control-plane `environment:`, next to `FIREWALL_ENGINE`)

**Interfaces:**
- Produces: `logging.New(w io.Writer, format, level string) (*slog.Logger, error)`.

- [ ] **Step 1: Write the failing tests** (`logging_test.go`)

```go
package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewJSONIsTheDefault(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "", "")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("iptables INPUT handed over to nftables (2 rules removed)", "k", 1)
	l.Debug("hidden at info level")
	var line map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("default output must be one JSON line: %v\n%s", err, buf.String())
	}
	if line["msg"] != "iptables INPUT handed over to nftables (2 rules removed)" || line["level"] != "INFO" || line["k"] != float64(1) {
		t.Fatalf("line = %v", line)
	}
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("debug must be filtered at the default info level")
	}
}

func TestNewTextAndLevels(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "TEXT", "warn")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("dropped")
	l.Warn("kept")
	out := buf.String()
	if strings.Contains(out, "dropped") || !strings.Contains(out, "level=WARN msg=kept") {
		t.Fatalf("text/warn output = %q", out)
	}
	if _, err := New(&buf, "json", "debug"); err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsUnknownValues(t *testing.T) {
	var buf bytes.Buffer
	if _, err := New(&buf, "xml", "info"); err == nil {
		t.Error("unknown LOG_FORMAT must be an error")
	}
	if _, err := New(&buf, "json", "verbose"); err == nil {
		t.Error("unknown LOG_LEVEL must be an error")
	}
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure in `internal/shared/logging`: `undefined: New`.

- [ ] **Step 3: Implement** (`logging.go`)

```go
// Package logging builds the control plane's structured logger.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a logger writing JSON (format "" or "json") or logfmt-style
// text ("text") at level debug, info (default), warn or error.
func New(w io.Writer, format, level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		lvl = slog.LevelInfo
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown LOG_LEVEL %q (use debug, info, warn or error)", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("unknown LOG_FORMAT %q (use json or text)", format)
}
```

Wire it into `main.go`. Add the imports `"log/slog"` and `"github.com/novusgate/novusgate/internal/shared/logging"`, and make these the first statements of `runServer`:

```go
	// Structured logs for the server; slog.SetDefault also routes the
	// standard log package. A typo in a logging variable must not stop the
	// VPN control plane: fall back to JSON/info and say so.
	logger, logErr := logging.New(os.Stdout, os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))
	if logErr != nil {
		logger, _ = logging.New(os.Stdout, "", "")
	}
	slog.SetDefault(logger)
	if logErr != nil {
		slog.Warn(logErr.Error() + "; using LOG_FORMAT=json LOG_LEVEL=info")
	}
```

In `docker-compose.yml`, under the control-plane `environment:` directly below `FIREWALL_ENGINE: ${FIREWALL_ENGINE:-iptables}`, add (same indentation):

```yaml
      LOG_FORMAT: ${LOG_FORMAT:-json}
      LOG_LEVEL: ${LOG_LEVEL:-info}
```

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `ok …/internal/shared/logging` and every other package `ok`.

Run: `grep -n "LOG_FORMAT\|LOG_LEVEL" server/deployments/docker/docker-compose.yml`
Expected: two lines, both under the control-plane `environment:`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/shared/logging server/cmd/control-plane/main.go server/deployments/docker/docker-compose.yml
git commit -m "feat: add structured slog logger with LOG_FORMAT and LOG_LEVEL"
```

---

### Task 2: Request log and panic recovery middleware

**Files:**
- Create: `server/internal/controlplane/api/rest/middleware.go`, `server/internal/controlplane/api/rest/middleware_test.go`
- Modify: `server/internal/controlplane/api/rest/handlers.go` (delete the no-op `LoggingMiddleware` at ~1713-1722; `setupRoutes` middleware lines ~262-264)
- Modify: `server/cmd/control-plane/main.go:205`

**Interfaces:**
- Produces: `LoggingMiddleware(http.Handler) http.Handler` (same exported name; the old no-op body is replaced), `RecoverMiddleware(http.Handler) http.Handler`.
- Consumes: `errorResponse` (handlers.go), `newContractServer`/`callAs` (contract_test.go, P2a).

- [ ] **Step 1: Write the failing tests** (`middleware_test.go`)

```go
package rest

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// captureLogs routes slog to a buffer for one test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return &buf
}

func TestRequestLogNeverContainsSecrets(t *testing.T) {
	logs := captureLogs(t)
	s, _, _ := newContractServer(t)
	seedContract(t, s.store)
	req := httptest.NewRequest("POST", "/api/v1/auth/login?token=query-secret&password=query-pw",
		strings.NewReader(`{"username":"contract-user","password":"contract-pw-1"}`))
	req.Header.Set("Authorization", "Bearer header-secret")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	out := logs.String()
	for _, secret := range []string{"query-secret", "query-pw", "header-secret", "contract-pw-1", adminToken} {
		if strings.Contains(out, secret) {
			t.Fatalf("log leaks %q:\n%s", secret, out)
		}
	}
	if strings.Count(out, `"msg":"http request"`) != 1 ||
		!strings.Contains(out, `"method":"POST"`) || !strings.Contains(out, `"path":"/api/v1/auth/login"`) ||
		!strings.Contains(out, `"status":200`) {
		t.Fatalf("want exactly one request line with method, path and status:\n%s", out)
	}
}

func TestRecoverMiddleware(t *testing.T) {
	logs := captureLogs(t)
	r := mux.NewRouter()
	r.Use(LoggingMiddleware, RecoverMiddleware)
	r.HandleFunc("/boom", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
	r.HandleFunc("/abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))
	if rec.Code != 500 || strings.TrimSpace(rec.Body.String()) != `{"error":"internal server error"}` {
		t.Fatalf("panic must become a 500 JSON error, got %d %s", rec.Code, rec.Body)
	}
	out := logs.String()
	if !strings.Contains(out, `"msg":"panic in handler"`) || !strings.Contains(out, "kaboom") ||
		!strings.Contains(out, "goroutine") || !strings.Contains(out, `"status":500`) {
		t.Fatalf("panic must be logged with its stack and the request line with 500:\n%s", out)
	}

	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("http.ErrAbortHandler must be re-panicked for net/http, got %v", v)
		}
	}()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/abort", nil))
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure, `undefined: RecoverMiddleware`. After a temporary empty stub it would fail with "want exactly one request line" (today's `LoggingMiddleware` logs nothing). The build failure is enough.

- [ ] **Step 3: Implement**

Delete the old `LoggingMiddleware` (the `// LoggingMiddleware logs requests` comment and the function, handlers.go ~1713-1722). Create `middleware.go`:

```go
package rest

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// statusRecorder captures the response status and size for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status, bytes int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// LoggingMiddleware writes one structured line per request. Query strings,
// headers and bodies are never logged: they carry tokens and passwords.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case r.URL.Path == "/health":
			level = slog.LevelDebug // polled; keep it out of info logs
		}
		slog.Log(r.Context(), level, "http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status, "bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr)
	})
}

// RecoverMiddleware turns a handler panic into a 500 JSON error and logs it
// with its stack. http.ErrAbortHandler is re-panicked: net/http uses it to
// abort a response on purpose.
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			slog.Error("panic in handler", "method", r.Method, "path", r.URL.Path,
				"panic", fmt.Sprint(v), "stack", string(debug.Stack()))
			errorResponse(w, http.StatusInternalServerError, "internal server error")
		}()
		next.ServeHTTP(w, r)
	})
}
```

In `setupRoutes`, replace the three `s.router.Use(...)` lines with:

```go
	// Order: the request log wraps everything (it records the 500 that
	// RecoverMiddleware writes), then panic recovery, then auth.
	s.router.Use(LoggingMiddleware, RecoverMiddleware, APIKeyMiddleware, AuthMiddleware)
```

In `main.go:205`, replace `Handler:      rest.LoggingMiddleware(rest.AuthMiddleware(apiServer.Router())),` with `Handler:      apiServer.Router(),`. The router already applies these middlewares, and they ran twice. Every request matches a route (the `PathPrefix("/")` SPA catch-all has no method restriction), so router middleware covers all requests, including `OPTIONS` preflight.

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`. `TestContract` is unchanged (middleware does not alter bodies).

Run: `grep -n "LoggingMiddleware\|AuthMiddleware" server/cmd/control-plane/main.go`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest/middleware.go server/internal/controlplane/api/rest/middleware_test.go server/internal/controlplane/api/rest/handlers.go server/cmd/control-plane/main.go
git commit -m "feat: log each request and recover handler panics"
```

---

### Task 3: `/health` checks the database, WireGuard and the firewall engine

**Files:**
- Modify: `server/internal/controlplane/store/store.go` (add `Ping`)
- Modify: `server/internal/controlplane/firewall/engine.go` (add `Ready`)
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`handleHealth`, ~1091; add `interfaceUp`)
- Modify: `server/internal/controlplane/api/rest/contract_test.go` (stub `interfaceUp` in `newContractServer`)
- Create: `server/internal/controlplane/api/rest/health_test.go`
- Modify: `server/internal/controlplane/api/rest/testdata/contract/health.json` (regenerated)

**Interfaces:**
- Produces:
  - `(*store.Store).Ping(ctx context.Context) error`;
  - `(*firewall.Engine).Ready() bool`;
  - `var interfaceUp func(name string) bool` (rest).
- Consumes: `newContractServer`, `seedContract`, `callAs`, `newEngineServer`, `call` (existing test helpers).

- [ ] **Step 1: Write the failing tests** (`health_test.go`)

```go
package rest

import (
	"encoding/json"
	"testing"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
)

type healthBody struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Checks  struct {
		Database  struct{ OK bool `json:"ok"` } `json:"database"`
		WireGuard struct {
			OK         bool              `json:"ok"`
			Interfaces map[string]string `json:"interfaces"`
		} `json:"wireguard"`
		Firewall struct {
			OK      bool   `json:"ok"`
			Mode    string `json:"mode"`
			Ready   *bool  `json:"ready"`
			Pending *bool  `json:"pending"`
		} `json:"firewall"`
	} `json:"checks"`
}

func getHealth(t *testing.T, s *Server) healthBody {
	t.Helper()
	rec := callAs(t, s, "GET", "/health", "", false)
	if rec.Code != 200 {
		t.Fatalf("/health = %d %s (it always answers 200)", rec.Code, rec.Body)
	}
	var h healthBody
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHealthReportsInterfaces(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	interfaceUp = func(name string) bool { return name == "wg66" }
	h := getHealth(t, s)
	if h.Version != "0.1.0" || !h.Checks.Database.OK || h.Checks.Firewall.Mode != "iptables" || !h.Checks.Firewall.OK {
		t.Fatalf("health = %+v", h)
	}
	if h.Checks.WireGuard.OK || h.Checks.WireGuard.Interfaces["wg66"] != "up" || h.Checks.WireGuard.Interfaces["wg68"] != "down" || h.Status != "degraded" {
		t.Fatalf("a down interface makes the system degraded: %+v", h)
	}
	interfaceUp = func(string) bool { return true }
	if h := getHealth(t, s); h.Status != "healthy" || !h.Checks.WireGuard.OK {
		t.Fatalf("all up must be healthy: %+v", h)
	}
}

func TestHealthWhenDatabaseIsDown(t *testing.T) {
	s, st, _ := newContractServer(t)
	st.Close()
	h := getHealth(t, s)
	if h.Status != "degraded" || h.Checks.Database.OK {
		t.Fatalf("a closed database must be reported, not hidden: %+v", h)
	}
}

func TestHealthReportsFirewallEngine(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeNft)
	origUp := interfaceUp
	interfaceUp = func(string) bool { return true }
	t.Cleanup(func() { interfaceUp = origUp })
	h := getHealth(t, s)
	if h.Checks.Firewall.Mode != "nft" || h.Checks.Firewall.Ready == nil || !*h.Checks.Firewall.Ready ||
		h.Checks.Firewall.Pending == nil || *h.Checks.Firewall.Pending || !h.Checks.Firewall.OK {
		t.Fatalf("ready nft engine: %+v", h.Checks.Firewall)
	}
	old := s.firewall
	s.SetFirewall(&firewall.Engine{Mode: firewall.ModeNft, Store: old.Store, Applier: old.Applier, Now: old.Now, Detect: old.Detect})
	if h := getHealth(t, s); h.Checks.Firewall.OK || h.Status != "degraded" {
		t.Fatalf("an engine that is not ready is degraded: %+v", h)
	}
}
```

In `newContractServer` (contract_test.go), next to the other stubs and restored in the same `t.Cleanup`, add `origUp := interfaceUp` and `interfaceUp = func(string) bool { return true }`. Add `interfaceUp = origUp` to the cleanup function.

`newEngineServer` (firewall_engine_test.go) does not stub `interfaceUp`. `TestHealthReportsFirewallEngine` sets and restores it itself, as shown above.

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure, `undefined: interfaceUp`.

- [ ] **Step 3: Implement**

`store.go`:

```go
// Ping checks that the database answers (used by /health).
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}
```

`firewall/engine.go`, next to `MarkReady`:

```go
// Ready reports whether startup finished and changes are accepted.
func (e *Engine) Ready() bool { return e.ready.Load() }
```

`handlers.go`: replace `handleHealth` with the code below. Keep the imports used; add `"net"` only if it is missing (it is present).

```go
// interfaceUp reports whether a network interface exists and is up. The
// control plane shares the host's network namespace (replaced in tests).
var interfaceUp = func(name string) bool {
	ifc, err := net.InterfaceByName(name)
	return err == nil && ifc.Flags&net.FlagUp != 0
}

// handleHealth always answers 200 (API contract); "status" is "healthy" or
// "degraded" and "checks" says why. It is public, so it reports states only,
// never error texts.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	healthy := true
	checks := map[string]interface{}{}

	if s.store.Ping(ctx) != nil {
		healthy = false
		checks["database"] = map[string]interface{}{"ok": false}
	} else {
		checks["database"] = map[string]interface{}{"ok": true}
		wgOK := true
		interfaces := map[string]string{}
		if networks, err := s.store.ListNetworks(ctx); err != nil {
			wgOK = false
		} else {
			for _, n := range networks {
				if n.InterfaceName == "" {
					continue
				}
				state := "up"
				if !interfaceUp(n.InterfaceName) {
					state, wgOK = "down", false
				}
				interfaces[n.InterfaceName] = state
			}
		}
		healthy = healthy && wgOK
		checks["wireguard"] = map[string]interface{}{"ok": wgOK, "interfaces": interfaces}
	}

	fw := map[string]interface{}{"ok": true, "mode": string(firewall.ModeIptables)}
	if s.firewall != nil {
		fw["mode"] = string(s.firewall.Mode)
		if s.firewall.Mode == firewall.ModeNft {
			ready := s.firewall.Ready()
			_, pending := s.firewall.PendingChange()
			fw["ok"], fw["ready"], fw["pending"] = ready, ready, pending
			healthy = healthy && ready
		}
	}
	checks["firewall"] = fw

	status := "healthy"
	if !healthy {
		status = "degraded"
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"status": status, "version": "0.1.0", "checks": checks})
}
```

- [ ] **Step 4: Run them, verify they pass, and update the contract**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: the three health tests pass. `TestContract` fails only on `health` (new `checks`).

Run: `bash server/scripts/update-contracts.sh`, then `git diff server/internal/controlplane/api/rest/testdata/contract`.
Expected:
- only `health.json` changed;
- `status` and `version` are unchanged (`healthy`, `0.1.0`);
- `checks` was added with `database.ok: true`, `firewall {mode: iptables, ok: true}` and `wireguard {ok: true, interfaces: {wg66: up, wg68: up}}`. `TestContract` seeds before the cases run, and the stub reports every interface up.

Run the suite again. Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/store/store.go server/internal/controlplane/firewall/engine.go server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/health_test.go server/internal/controlplane/api/rest/contract_test.go server/internal/controlplane/api/rest/testdata/contract/health.json
git commit -m "feat: report database, WireGuard and firewall state in /health"
```

---

### Task 4: Runtime code logs through slog

**Files:**
- Create: `server/internal/shared/logging/noprint_test.go`
- Modify (prints → slog):
  - `server/internal/controlplane/api/rest/handlers.go`, `config_handlers.go`, `firewall_engine.go`, `firewall_handlers.go`;
  - `server/internal/controlplane/firewall/engine.go`, `cutover.go`;
  - `server/internal/controlplane/store/migrations.go`;
  - `server/internal/netctl/nft/safeapply.go`;
  - `server/internal/wireguard/manager.go`;
  - `server/cmd/control-plane/main.go` (only the functions `runServer` and `bootstrapSystem`).

**Interfaces:**
- Consumes: the default logger set by `main.go` (Task 1).

- [ ] **Step 1: Write the failing test** (`noprint_test.go`)

```go
package logging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runtimeDirs hold server runtime code: it must log through slog so every
// line is structured and filtered by LOG_LEVEL. CLI output for the user
// (cmd/control-plane commands other than serve) may keep fmt.
var runtimeDirs = []string{
	"../../controlplane/api/rest",
	"../../controlplane/firewall",
	"../../controlplane/store",
	"../../netctl/nft",
	"../../wireguard",
}

// serverFuncs are the server-runtime functions in cmd/control-plane/main.go.
var serverFuncs = map[string]bool{"runServer": true, "bootstrapSystem": true}

func TestRuntimeCodeLogsThroughSlog(t *testing.T) {
	var bad []string
	check := func(fset *token.FileSet, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			forbidden := (pkg.Name == "log" && (strings.HasPrefix(name, "Print") || strings.HasPrefix(name, "Fatal"))) ||
				(pkg.Name == "fmt" && strings.HasPrefix(name, "Print"))
			if pkg.Name == "fmt" && strings.HasPrefix(name, "Fprint") && len(call.Args) > 0 {
				if w, ok := call.Args[0].(*ast.SelectorExpr); ok {
					if x, ok := w.X.(*ast.Ident); ok && x.Name == "os" && (w.Sel.Name == "Stdout" || w.Sel.Name == "Stderr") {
						forbidden = true
					}
				}
			}
			if forbidden {
				bad = append(bad, fset.Position(call.Pos()).String()+": "+pkg.Name+"."+name)
			}
			return true
		})
	}
	for _, dir := range runtimeDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files in %s: %v", dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			check(fset, file)
		}
	}
	mainGo := "../../../cmd/control-plane/main.go"
	if _, err := os.Stat(mainGo); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGo, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && serverFuncs[fn.Name.Name] {
			check(fset, fn)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("runtime code must log through log/slog, found %d direct prints:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `FAIL: TestRuntimeCodeLogsThroughSlog` listing the direct prints. Today there are about 110: about 90 `fmt.Print*`, 9 `log.Printf`, and the `fmt.Fprintf(os.Stderr…)` in main.go.

- [ ] **Step 3: Convert every listed call mechanically**

Rules:
1. **Calls.**
   - `fmt.Printf(format, args...)` with a trailing `\n` in the format → `slog.<Level>(fmt.Sprintf(format-without-\n, args...))`.
   - `fmt.Println(s)` → `slog.<Level>(s)`.
   - `fmt.Fprintf(os.Stderr, …)` / `log.Printf(…)` → the same pattern.
   - The message text stays **identical**: runbooks and operators grep for it.
2. **Level**, decided by the message text:
   - `Error`: the text starts with or contains `Error`, `ERROR`, `failed`, `Failed` or `startup failed`. Exception: lines that also contain `(will retry)` are `Warn`.
   - `Warn`: it contains `Warning`, `warning`, `WARNING` or `will retry`.
   - `Info`: everything else, including `Note:`, `[INFO]` and `SUCCESS`.
3. **Imports.** Add `"log/slog"` where needed. Remove `"log"` where it becomes unused; keep `"fmt"` wherever `fmt.Sprintf`/`Errorf` is still used. The compiler decides.
4. **CLI output stays.** Do not touch `fmt` in `cmd/control-plane` outside `runServer`/`bootstrapSystem` (`initNetwork`, `runMigrations`, the version command, `firewall_cmd.go`). `store/migrations.go` runs inside both `serve` and `migrate`, so it converts, and in the `migrate` CLI its lines then appear through the default slog text handler.

   For the `migrate` CLI path only: in `runMigrations`, before anything prints, add `slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))`. That keeps that command's output readable.

Examples (exact):

```go
// before
fmt.Printf("[Firewall] warning: could not remove legacy iptables VPN rules (will retry): %v\n", err)
// after
slog.Warn(fmt.Sprintf("[Firewall] warning: could not remove legacy iptables VPN rules (will retry): %v", err))

// before
fmt.Printf("[Firewall] iptables INPUT handed over to nftables (%d rules removed)\n", n)
// after
slog.Info(fmt.Sprintf("[Firewall] iptables INPUT handed over to nftables (%d rules removed)", n))

// before
log.Printf("firewall: rollback failed, host timer will restore: %v", err)
// after
slog.Error(fmt.Sprintf("firewall: rollback failed, host timer will restore: %v", err))

// before (main.go, inside runServer)
fmt.Fprintf(os.Stderr, "[Firewall] startup failed: %v\n", err)
// after
slog.Error(fmt.Sprintf("[Firewall] startup failed: %v", err))
```

Run `grep -rn "fmt.Printf\|fmt.Println\|log.Printf" <file>` per file while converting. The test in Step 1 is the final authority.

- [ ] **Step 4: Run it and verify it passes**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `ok …/internal/shared/logging` and all other packages `ok`.

Run: `grep -rn "iptables INPUT handed over to nftables\|imported %d panel rules\|host not ready for FIREWALL_ENGINE=nft" server/internal server/cmd --include=*.go | grep -v _test`
Expected: each runbook message is still present verbatim.

- [ ] **Step 5: Commit**

```bash
git add server/internal server/cmd
git commit -m "refactor: route runtime logs through slog"
```

---

### Task 5: Documentation

**Files:**
- Modify: `docs/api.md` (`/health` section), `docs/architecture.md` (logging, middleware, health), `docs/active-context.md`, `docs/runbooks/p3b2-firewall-cutover.md` (log grep note)

- [ ] **Step 1: Write**
  - **`docs/api.md`:** a `GET /health` section.
    - Fields: `status` (`healthy`/`degraded`), `version`, `checks.database.ok`, `checks.wireguard.{ok,interfaces}`, `checks.firewall.{ok,mode,ready?,pending?}`.
    - Always 200; public; no error texts.
    - The reconciler check comes in P2c.
  - **`docs/architecture.md`:** a "Log və müşahidə (P2b)" section.
    - `LOG_FORMAT` (json default, text) and `LOG_LEVEL` (debug/info/warn/error; an invalid value falls back to JSON/info with a warning).
    - One `http request` line per request (method, path, status, bytes, duration_ms, remote; never query, headers or body); `/health` logs at debug.
    - `RecoverMiddleware` turns a panic into a 500 and logs it with its stack.
    - Middleware runs once (the `main.go` double wrap was removed).
    - `TestRuntimeCodeLogsThroughSlog` guards runtime code.
  - **`docs/runbooks/p3b2-firewall-cutover.md`:** add one sentence at the top. "Log sətirləri JSON-dur (`LOG_FORMAT=json`); `docker logs novusgate-control-plane | grep '<mətn>'` eyni işləyir, oxumaq üçün `.env`-ə `LOG_FORMAT=text` yaz."
  - **`docs/active-context.md`:** a session block plus table rows.

- [ ] **Step 2: Verify**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`.

- [ ] **Step 3: Commit**

```bash
git add docs/api.md docs/architecture.md docs/active-context.md docs/runbooks/p3b2-firewall-cutover.md
git commit -m "docs: document P2b logging, middleware and health"
```

---

## Out of scope
- **P2c:** the reconciler and its health check; the expiry job.
- **P2d:** the unified error format, the service layer, OpenAPI.
- **Turning `fmt.Sprintf` messages into fully structured attributes** (e.g. `"error", err`). This is a later, per-area refactor once the messages are no longer grepped by runbooks.
