# P3b-2 Firewall Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `FIREWALL_ENGINE=nft` a complete, reboot- and update-safe firewall. nftables takes INPUT filtering over from iptables. A boot unit loads the ruleset before Docker. fail2ban follows the real SSH ports. Going back to iptables is a single scripted step. The open P3a/P3b-1 review items are closed.

**Architecture:**
- The control plane hands iptables INPUT over to `table inet novusgate` only after nftables has applied once (`Engine.AfterApply`), and only on a host that passes `CheckHost`. `CheckHost` requires host nft >= 1.0.2, the boot unit enabled, and an iptables nf_tables backend.
- `setup-firewall.sh` is the host side. It runs on install and on every server Update. It installs nftables and the boot unit, writes the fail2ban jail override, leaves iptables alone in nft mode, and removes the nft engine in iptables mode.

**Tech Stack:** Go 1.23 (control plane), nftables 1.0.2+, iptables (nf_tables backend), systemd, bash, PostgreSQL 16 (tests), React/TS (one client fix).

**Spec:** `docs/superpowers/specs/2026-10-13-p3-firewall-design.md`. §3, §6 (P3b row), §6a, §6b and §7 drive this plan.

## Global Constraints

- **Default mode:** `FIREWALL_ENGINE` defaults to `iptables`. Go code paths in iptables mode stay unchanged, except Task 4, which adds SSH-port protection to Close Port and Delete.
- **No new Go modules, npm packages or host packages** except `nftables`, which spec §6a requires.
- **Never enable `nftables.service`.** Its default `/etc/nftables.conf` runs `flush ruleset`, which would wipe Docker's rules.
- **Language:** code comments in English. Docs in Azerbaijani with full diacritics.
- **Test environment:**
  - Go runs only in Docker: `bash server/scripts/test-with-postgres.sh` (gofmt + vet + build + `go test -p 1`, real Postgres, `NFT_CHECK=1`).
  - Shell tests: `MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/deployments/docker:/w -w /w ubuntu:24.04 bash tests/setup-firewall_test.sh`.
  - The WSL docker shim expands `$` and `|` in arguments, so shell logic goes into script files.
- **No `--privileged` containers.** `--cap-add NET_ADMIN` is allowed, as `test-with-postgres.sh` already uses it.
- **Commits:** no `Co-Authored-By`, "Claude", "Anthropic" or "AI generated" lines. One logical change per commit. `*.go`, `*.sh` and `*.nft` files are LF (`.gitattributes`).
- **Fail closed:** when a host precondition is missing, nft mode refuses to start. iptables keeps enforcing and nothing on the host changes.

## Review Focus

1. **Reboot after cutover.** netfilter-persistent restores the saved iptables (INPUT ACCEPT, only f2b jumps) and `novusgate-firewall.service` loads `/etc/novusgate/firewall.nft` before Docker. Expect: no window where the host is open, and no leftover INPUT DROP. Pinned by Task 6 (unit content and ordering) and Task 2 (saves after the hand-over).
2. **Server Update in nft mode.** `setup-firewall.sh` runs on every server Update. Expect: it must not flush iptables, set INPUT DROP or restart Docker once nft owns INPUT. Pinned by Task 6, case "nft mode with ruleset".
3. **Control-plane restart after cutover.** The hand-over runs again. Expect: idempotent, so it deletes nothing new and never touches fail2ban jumps. Pinned by Task 2, `TestCutoverIsIdempotentAndKeepsFail2ban`.
4. **Going back to iptables.** Expect: `setup-firewall.sh` with `FIREWALL_ENGINE=iptables` first rebuilds the iptables baseline (INPUT DROP last) and only then deletes `table inet novusgate`, so the host is never unfiltered. Pinned by Task 6, case "iptables mode reverts".
5. **Host not ready.** Covers Ubuntu 20.04 (nft 0.9.3, legacy iptables), a missing boot unit and a missing nft. Expect: nft mode refuses, nothing is imported or applied, and firewall changes return 409. Pinned by Task 2, `TestCheckHost*` and `TestStartFirewallRefusesUnreadyHost`.

---

## File Structure

| File | Responsibility |
|---|---|
| `server/internal/controlplane/firewall/engine.go` (modify) | readiness gate, post-apply robustness |
| `server/internal/controlplane/firewall/cutover.go` (create) | `CheckHost`, `CutoverIptables`, `BootUnit` |
| `server/internal/controlplane/firewall/cutover_test.go` (create) | fake-runner tests for the two functions |
| `server/internal/controlplane/api/rest/firewall_engine.go` (modify) | startup order, AfterApply hand-over, error mapping, endpoint selection |
| `server/internal/controlplane/api/rest/firewall_v2_handlers.go` (modify) | duplicate forward 409, transactional service commit |
| `server/internal/controlplane/api/rest/firewall_v1_nft.go` (modify) | v1 display fixes |
| `server/internal/controlplane/api/rest/firewall_handlers.go` (modify) | legacy path protects detected SSH ports |
| `server/internal/controlplane/store/firewall.go` (modify) | `CreateFirewallServices` (one transaction) |
| `server/internal/netctl/nft/{compile,validate}.go` (modify) | M5: admin/API exception per real network interfaces |
| `server/internal/netctl/nft/testdata/{empty,v6only}.nft` (create) | M10 edge goldens |
| `server/scripts/nft-versions-check.sh`, `server/scripts/nft-versions-inner.sh` (create) | M10 cross-version check (nft 1.0.2 / 1.0.6 / 1.0.9, snapshot round trip) |
| `server/deployments/docker/setup-firewall.sh` (modify) | nftables, boot unit, fail2ban, nft-mode skip, iptables revert |
| `server/deployments/docker/tests/setup-firewall_test.sh` (modify) | cases for the above |
| `web/src/api/client.ts` (modify) | Delete rule calls the registered route |
| `docs/runbooks/p3b2-firewall-cutover.md` (create), `docs/api.md`, `docs/architecture.md`, `docs/active-context.md`, spec (modify) | docs |

---

### Task 1: Engine readiness gate and post-apply robustness (§6b.2, §6b.6)

The engine refuses changes until startup has finished the one-time iptables import. Without this gate, a reconcile triggered by a network change or an expiry before the import could run the INPUT hand-over (Task 2) and delete panel rules that were never imported. After an apply, a lost request context no longer leaves the change live but unsaved, and a failed boot-file write is reported as a warning.

**Files:**
- Modify: `server/internal/controlplane/firewall/engine.go`
- Modify: `server/internal/controlplane/firewall/engine_test.go`
- Modify: `server/internal/controlplane/api/rest/firewall_engine.go` (`engineError`, `StartFirewall`)
- Modify: `server/internal/controlplane/api/rest/firewall_engine_test.go` (`newEngineServer`)

**Interfaces:**
- Produces:
  - `firewall.ErrNotReady error`;
  - `(*Engine).MarkReady()`;
  - `finish` now returns `([]error, error)`, where the first value holds warnings.
- Produces: `engineError` maps `ErrNotReady` to 409.

- [ ] **Step 1: Write the failing tests** (append to `engine_test.go`; in `newHarness`, add `h.e.MarkReady()` just before `return h`)

```go
func TestEngineRefusesChangesUntilReady(t *testing.T) {
	h := newHarness(ModeNft)
	h.e = &Engine{Mode: ModeNft, Store: h.st, Applier: h.e.Applier, Now: h.e.Now, Detect: h.e.Detect}
	commits := 0
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Propose before MarkReady = %v, want ErrNotReady", err)
	}
	if len(h.r.applied) != 0 || commits != 0 {
		t.Fatal("nothing may be applied or stored before the engine is ready")
	}
	h.e.MarkReady()
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); err != nil {
		t.Fatal(err)
	}
}

// A request whose client disconnects must still store the live change.
func TestCommitIgnoresRequestCancellation(t *testing.T) {
	h := newHarness(ModeNft)
	ctx, cancel := context.WithCancel(context.Background())
	ch := Change{
		Mutate: func(st *State) error { return nil },
		Commit: func(c context.Context) error { cancel(); return c.Err() },
	}
	if _, err := h.e.Propose(ctx, ch, false, nil); err != nil {
		t.Fatalf("commit must not see the request's cancellation: %v", err)
	}
}

// A change that is live but could not be stored is undone by a reconcile.
func TestFailedCommitSchedulesReconcile(t *testing.T) {
	h := newHarness(ModeNft)
	ch := Change{
		Mutate: func(st *State) error { return nil },
		Commit: func(context.Context) error { return errors.New("db down") },
	}
	if _, err := h.e.Propose(context.Background(), ch, false, nil); err == nil {
		t.Fatal("a failed commit must be reported")
	}
	if len(h.timers) != 1 || h.timers[0].d != retryMin {
		t.Fatalf("a reconcile must restore the stored state, timers=%+v", h.timers)
	}
}

func TestPersistFailureIsAWarning(t *testing.T) {
	h := newHarness(ModeNft)
	h.e.Persist = func(string) error { return errors.New("read-only /etc") }
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
	if err != nil || commits != 1 {
		t.Fatalf("the change is live and stored; Persist failure must not be an error (err=%v)", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Error(), "boot-time ruleset") {
		t.Fatalf("warnings = %v", res.Warnings)
	}
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure `h.e.MarkReady undefined` / `undefined: ErrNotReady`.

- [ ] **Step 3: Implement in `engine.go`**

Add `"sync/atomic"` to the imports. Then add these declarations:

```go
	// ErrNotReady is returned until startup has finished the one-time
	// iptables import; changes before that could hand INPUT over to nftables
	// before the panel's iptables rules were copied.
	ErrNotReady = errors.New("the firewall engine is starting (iptables import pending); try again shortly")
```
(in the `var (...)` block with `ErrEngineDisabled`)

```go
	ready      atomic.Bool
```
(in the Engine struct, after `retryDelay`)

```go
// MarkReady lets Propose run; StartFirewall calls it after the import.
func (e *Engine) MarkReady() { e.ready.Store(true) }
```

In `Propose`, directly after the `ModeNft` check:

```go
	if !e.ready.Load() {
		return Result{}, ErrNotReady
	}
```

Split `scheduleRetry` into a locking wrapper and `scheduleRetryLocked` (same body, without `Lock`/`Unlock`):

```go
func (e *Engine) scheduleRetry() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scheduleRetryLocked()
}

// scheduleRetryLocked needs e.mu held.
func (e *Engine) scheduleRetryLocked() {
	if e.AfterFunc == nil || e.stopRetry != nil {
		return
	}
	if e.retryDelay == 0 {
		e.retryDelay = retryMin
	} else if e.retryDelay *= 2; e.retryDelay > retryMax {
		e.retryDelay = retryMax
	}
	e.stopRetry = e.AfterFunc(e.retryDelay, func() {
		e.mu.Lock()
		e.stopRetry = nil
		e.mu.Unlock()
		if _, err := e.ReconcileOrRetry(context.Background()); err != nil {
			log.Printf("firewall: reconcile retry failed: %v", err)
		}
	})
}
```

Replace `finish`:

```go
// finish runs after the host took a change: it stores it (detached from the
// request, so a disconnecting client cannot leave it unsaved), schedules the
// next expiry and writes the boot-time ruleset. It returns warnings and an
// error.
func (e *Engine) finish(ctx context.Context, commit func(context.Context) error, script string, st State) ([]error, error) {
	if e.stopRetry != nil {
		e.stopRetry()
		e.stopRetry = nil
	}
	e.retryDelay = 0
	if e.AfterApply != nil {
		e.AfterApply()
	}
	if commit != nil {
		if err := commit(context.WithoutCancel(ctx)); err != nil {
			// The host runs a change the database does not have; the
			// reconcile re-applies the stored state.
			e.scheduleRetryLocked()
			return nil, fmt.Errorf("firewall change applied but not saved (the stored state is re-applied shortly): %w", err)
		}
	}
	e.scheduleExpiry(st)
	if e.Persist != nil {
		if err := e.Persist(script); err != nil {
			return []error{fmt.Errorf("the boot-time ruleset was not written: %w", err)}, nil
		}
	}
	return nil, nil
}
```

Update the callers. In `Propose`:

```go
	extra, err := e.finish(ctx, ch.Commit, script, st)
	return Result{Warnings: append(warnings, extra...)}, err
```

In `Confirm`:

```go
	extra, err := e.finish(ctx, pc.commit, pc.script, pc.state)
	for _, w := range extra {
		log.Printf("firewall: %v", w)
	}
	return err
```

- [ ] **Step 4: Wire it in REST**

In `engineError` (`firewall_engine.go`), add `errors.Is(err, firewall.ErrNotReady),` to the 409 case.

In `StartFirewall`, `case firewall.ModeNft:`, insert directly after the import block (after the `if n > 0 || ...` print):

```go
		s.firewall.MarkReady()
```

In `newEngineServer` (`firewall_engine_test.go`), replace `s.SetFirewall(&firewall.Engine{...})` with:

```go
	e := &firewall.Engine{
		Mode: mode, Store: st, Applier: applier, Now: time.Now,
		Detect: func() (firewall.HostInfo, error) {
			return firewall.HostInfo{SSHPorts: []uint16{22}, Egress: "eth0"}, nil
		},
		Persist: func(string) error { return nil },
	}
	e.MarkReady()
	s.SetFirewall(e)
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `ok` for `api/rest`, `controlplane/firewall`, `store` and `netctl/nft`.

- [ ] **Step 6: Commit**

```bash
git add server/internal/controlplane/firewall/engine.go server/internal/controlplane/firewall/engine_test.go server/internal/controlplane/api/rest/firewall_engine.go server/internal/controlplane/api/rest/firewall_engine_test.go
git commit -m "fix: gate firewall changes until import and harden commits"
```

---

### Task 2: Host readiness check and iptables INPUT hand-over

**Files:**
- Create: `server/internal/controlplane/firewall/cutover.go`
- Create: `server/internal/controlplane/firewall/cutover_test.go`
- Modify: `server/internal/controlplane/api/rest/firewall_engine.go`
- Modify: `server/internal/controlplane/api/rest/firewall_engine_test.go`

**Interfaces:**
- Consumes: `nft.Runner` (`Run(stdin, name string, args ...string) (string, error)`), `nft.NsenterRunner`, `(*Engine).MarkReady`, `Engine.AfterApply` (Task 1 and P3b-1).
- Produces:
  - `firewall.BootUnit = "novusgate-firewall.service"`;
  - `firewall.CheckHost(r nft.Runner) error`;
  - `firewall.CutoverIptables(r nft.Runner) (int, error)`.
- Produces in `rest`: `var checkFirewallHost func() error` and `var cutoverIptables func() (int, error)`. Both are replaceable in tests.

- [ ] **Step 1: Write the failing tests** (`cutover_test.go`)

```go
package firewall

import (
	"errors"
	"strings"
	"testing"
)

// fakeHost answers commands from a table and records every call.
type fakeHost struct {
	out   map[string]string
	fail  map[string]bool
	calls []string
}

func (f *fakeHost) Run(_ string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if f.fail[cmd] {
		return f.out[cmd], errors.New("exit status 1")
	}
	return f.out[cmd], nil
}

func readyHost() *fakeHost {
	return &fakeHost{out: map[string]string{
		"nft --version":                                  "nftables v1.0.9 (Old Doc Yak #3)\n",
		"systemctl is-enabled novusgate-firewall.service": "enabled\n",
		"iptables -V":                                    "iptables v1.8.10 (nf_tables)\n",
	}, fail: map[string]bool{}}
}

func TestCheckHostAcceptsReadyHost(t *testing.T) {
	if err := CheckHost(readyHost()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckHostRefusesUnreadyHosts(t *testing.T) {
	cases := map[string]func(h *fakeHost){
		"nft missing":     func(h *fakeHost) { h.fail["nft --version"] = true },
		"nft 0.9.3":       func(h *fakeHost) { h.out["nft --version"] = "nftables v0.9.3 (Topsy)\n" },
		"nft 1.0.1":       func(h *fakeHost) { h.out["nft --version"] = "nftables v1.0.1 (Fearless Fosdick #3)\n" },
		"unit disabled":   func(h *fakeHost) { h.out["systemctl is-enabled novusgate-firewall.service"] = "disabled\n"; h.fail["systemctl is-enabled novusgate-firewall.service"] = true },
		"legacy iptables": func(h *fakeHost) { h.out["iptables -V"] = "iptables v1.8.4 (legacy)\n" },
		"no iptables":     func(h *fakeHost) { h.fail["iptables -V"] = true },
	}
	for name, mutate := range cases {
		h := readyHost()
		mutate(h)
		if err := CheckHost(h); err == nil {
			t.Errorf("%s: CheckHost must refuse", name)
		}
	}
	h := readyHost()
	h.out["nft --version"] = "nftables v1.0.2 (Lester Gooch)\n"
	if err := CheckHost(h); err != nil {
		t.Errorf("nft 1.0.2 is the supported minimum: %v", err)
	}
}

func TestCutoverAcceptsFirstThenDeletesPanelRules(t *testing.T) {
	h := &fakeHost{out: map[string]string{"iptables -S INPUT": "-P INPUT DROP\n" +
		"-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n" +
		"-A INPUT -i lo -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 443 -m comment --comment \"panel port\" -j ACCEPT\n" +
		"-A INPUT -s 198.51.100.9/32 -j DROP\n"}, fail: map[string]bool{}}
	n, err := CutoverIptables(h)
	if err != nil || n != 3 {
		t.Fatalf("CutoverIptables = %d, %v", n, err)
	}
	want := []string{
		"iptables -P INPUT ACCEPT",
		"iptables -S INPUT",
		"iptables -D INPUT 4",
		"iptables -D INPUT 3",
		"iptables -D INPUT 2",
		"netfilter-persistent save",
	}
	if strings.Join(h.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(h.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestCutoverIsIdempotentAndKeepsFail2ban(t *testing.T) {
	h := &fakeHost{out: map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n" +
		"-A INPUT -p tcp -m multiport --dports 22,2222 -j f2b-sshd\n"}, fail: map[string]bool{}}
	if n, err := CutoverIptables(h); err != nil || n != 0 {
		t.Fatalf("second hand-over = %d, %v", n, err)
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "iptables -D") {
			t.Fatalf("fail2ban jumps must stay: %s", c)
		}
	}
}

func TestCutoverStopsWhenPolicyCannotBeChanged(t *testing.T) {
	h := &fakeHost{out: map[string]string{}, fail: map[string]bool{"iptables -P INPUT ACCEPT": true}}
	if _, err := CutoverIptables(h); err == nil || len(h.calls) != 1 {
		t.Fatalf("no rule may be deleted while INPUT still drops (err=%v, calls=%v)", err, h.calls)
	}
}

func TestCutoverToleratesMissingPersistence(t *testing.T) {
	h := &fakeHost{out: map[string]string{"iptables -S INPUT": "-P INPUT DROP\n"},
		fail: map[string]bool{"netfilter-persistent save": true}}
	if _, err := CutoverIptables(h); err != nil {
		t.Fatalf("the next start repeats the hand-over; save failure is only logged: %v", err)
	}
}
```

In `firewall_engine_test.go`, add a stub to `newEngineServer`, extending the "Never touch the machine" block:

```go
	origCheck, origCutover := checkFirewallHost, cutoverIptables
	checkFirewallHost = func() error { return nil }
	cutoverIptables = func() (int, error) { return 0, nil }
	t.Cleanup(func() { checkFirewallHost, cutoverIptables = origCheck, origCutover })
```

Extend `TestLegacyVPNRulesStayUntilTheEngineApplies` to count the hand-over too:

```go
	handed := 0
	cutoverIptables = func() (int, error) { handed++; return 2, nil }
```
(Place it next to the `clearLegacyVPNRules` override. Before the first successful apply, assert `handed == 0`. After the two `reconcileFirewall` calls, assert `handed == 1`.)

Then add:

```go
func TestStartFirewallRefusesUnreadyHost(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	old := s.firewall
	s.SetFirewall(&firewall.Engine{Mode: firewall.ModeNft, Store: old.Store, Applier: old.Applier, Now: old.Now, Detect: old.Detect})
	checkFirewallHost = func() error { return errors.New("host nftables v0.9.3 is older than 1.0.2") }
	if err := s.StartFirewall(context.Background()); err == nil {
		t.Fatal("startup must refuse an unready host")
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/open", `{"port":443,"protocol":"tcp"}`); rec.Code != http.StatusConflict {
		t.Fatalf("changes must wait for a ready engine, got %d", rec.Code)
	}
	if r.last() != "" {
		t.Fatal("nothing may be applied on an unready host")
	}
}
```
(Add `"errors"` to the test imports.)

- [ ] **Step 2: Run the tests and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure `undefined: CheckHost`, `undefined: checkFirewallHost`.

- [ ] **Step 3: Implement `cutover.go`**

```go
package firewall

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// BootUnit loads PersistPath on the host before Docker starts; it is
// installed by setup-firewall.sh.
const BootUnit = "novusgate-firewall.service"

// minHostNft is the oldest nft whose parser accepts the compiled ruleset and
// the rollback snapshot (verified by scripts/nft-versions-check.sh).
var minHostNft = [3]int{1, 0, 2}

var nftVersionRe = regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`)

// CheckHost refuses nft mode on a host that could not keep the firewall
// across a reboot or a rollback: host nft older than 1.0.2 (Ubuntu 20.04),
// a missing boot unit, or iptables on the legacy backend (whose rules the
// container's iptables cannot see). r must run on the host (nsenter).
func CheckHost(r nft.Runner) error {
	out, err := r.Run("", "nft", "--version")
	if err != nil {
		return fmt.Errorf("nftables is not installed on the host (run Center → Update, which runs setup-firewall.sh): %w", err)
	}
	m := nftVersionRe.FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("cannot read the host nftables version from %q", strings.TrimSpace(out))
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	if v[0] < minHostNft[0] || (v[0] == minHostNft[0] && (v[1] < minHostNft[1] || (v[1] == minHostNft[1] && v[2] < minHostNft[2]))) {
		return fmt.Errorf("host nftables %s is older than 1.0.2 (Ubuntu 20.04?): FIREWALL_ENGINE=nft is not supported on this host", strings.TrimSpace(out))
	}
	if out, err := r.Run("", "systemctl", "is-enabled", BootUnit); err != nil || strings.TrimSpace(out) != "enabled" {
		return fmt.Errorf("%s is not enabled on the host (run Center → Update, which runs setup-firewall.sh); without it the host would boot without its firewall", BootUnit)
	}
	out, err = r.Run("", "iptables", "-V")
	if err != nil {
		return fmt.Errorf("cannot read the host iptables backend: %w", err)
	}
	if !strings.Contains(out, "nf_tables") {
		return fmt.Errorf("host iptables %q is not on the nf_tables backend; FIREWALL_ENGINE=nft is not supported on this host", strings.TrimSpace(out))
	}
	return nil
}

// CutoverIptables hands INPUT filtering from iptables to table inet
// novusgate, which must already be applied. The policy becomes ACCEPT first
// (nftables already drops by default), so removing the rules never drops an
// established connection. Then every INPUT rule except fail2ban's jumps is
// deleted, and the result is saved for boot. It is idempotent, and every
// control-plane start repeats it. It returns the number of deleted rules.
func CutoverIptables(r nft.Runner) (int, error) {
	if _, err := r.Run("", "iptables", "-P", "INPUT", "ACCEPT"); err != nil {
		return 0, fmt.Errorf("set iptables INPUT policy to ACCEPT: %w", err)
	}
	out, err := r.Run("", "iptables", "-S", "INPUT")
	if err != nil {
		return 0, fmt.Errorf("read iptables INPUT: %w", err)
	}
	var nums []int
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		n++
		if strings.Contains(line, " -j f2b-") {
			continue
		}
		nums = append(nums, n)
	}
	// Delete from the bottom, so the remaining rule numbers stay valid.
	for i := len(nums) - 1; i >= 0; i-- {
		if _, err := r.Run("", "iptables", "-D", "INPUT", strconv.Itoa(nums[i])); err != nil {
			return len(nums) - 1 - i, fmt.Errorf("delete iptables INPUT rule %d: %w", nums[i], err)
		}
	}
	if _, err := r.Run("", "netfilter-persistent", "save"); err != nil {
		log.Printf("firewall: netfilter-persistent save failed (the next start repeats the hand-over): %v", err)
	}
	return len(nums), nil
}
```

- [ ] **Step 4: Wire it into REST** (`firewall_engine.go`)

Add these next to `clearLegacyVPNRules`:

```go
// checkFirewallHost and cutoverIptables run on the host (replaced in tests).
var checkFirewallHost = func() error { return firewall.CheckHost(nft.NsenterRunner{}) }

var cutoverIptables = func() (int, error) { return firewall.CutoverIptables(nft.NsenterRunner{}) }
```

Replace the `e.AfterApply` closure in `SetFirewall`:

```go
	handedOver := false // guarded by the engine lock AfterApply runs under
	e.AfterApply = func() {
		if handedOver {
			return
		}
		if err := clearLegacyVPNRules(s); err != nil {
			fmt.Printf("[Firewall] warning: could not remove legacy iptables VPN rules (will retry): %v\n", err)
			return
		}
		n, err := cutoverIptables()
		if err != nil {
			fmt.Printf("[Firewall] warning: iptables INPUT hand-over failed (will retry): %v\n", err)
			return
		}
		fmt.Printf("[Firewall] iptables INPUT handed over to nftables (%d rules removed)\n", n)
		handedOver = true
	}
```

Update the doc comment of `SetFirewall`. The last sentence becomes: "the legacy iptables VPN rules and INPUT filtering are handed over only after nftables first applies."

In `StartFirewall`, `case firewall.ModeNft:`, insert as the first statement:

```go
		if err := checkFirewallHost(); err != nil {
			return fmt.Errorf("host not ready for FIREWALL_ENGINE=nft (iptables keeps enforcing): %w", err)
		}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add server/internal/controlplane/firewall/cutover.go server/internal/controlplane/firewall/cutover_test.go server/internal/controlplane/api/rest/firewall_engine.go server/internal/controlplane/api/rest/firewall_engine_test.go
git commit -m "feat: hand iptables INPUT over to nftables on ready hosts"
```

---

### Task 3: REST fixes from the P3b-1 review (§6b.1, §6b.2, §6b.3, §6b.5, §6b.7)

**Files:**
- Modify: `server/internal/controlplane/store/firewall.go`, `server/internal/controlplane/store/firewall_test.go`
- Modify: `server/internal/controlplane/api/rest/firewall_v2_handlers.go`
- Modify: `server/internal/controlplane/api/rest/firewall_engine.go` (`errConflict`, `wireGuardEndpointFor`)
- Modify: `server/internal/controlplane/api/rest/firewall_v1_nft.go`
- Modify: `server/internal/controlplane/api/rest/firewall_engine_test.go`
- Modify: `web/src/api/client.ts:285-288`

**Interfaces:**
- Produces:
  - `(*store.Store).CreateFirewallServices(ctx, svcs []*models.FirewallService) error` (one transaction);
  - `errConflict` → 409;
  - `endpointForAddr(peers []wireguard.PeerStatus, addr netip.Addr) (netip.Addr, bool)`;
  - `displayPrefix(string) string`.

- [ ] **Step 1: Write the failing tests**

Add to `store/firewall_test.go` (`newTestStore` is the file's existing helper):

```go
func TestCreateFirewallServicesIsAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ok := &models.FirewallService{Protocol: "tcp", PortFrom: 443, PortTo: 443}
	bad := &models.FirewallService{Protocol: "xyz", PortFrom: 1, PortTo: 1} // violates CHECK (protocol IN ('tcp', 'udp'))
	if err := s.CreateFirewallServices(ctx, []*models.FirewallService{ok, bad}); err == nil {
		t.Fatal("an invalid service must fail the whole insert")
	}
	if got, _ := s.ListFirewallServices(ctx); len(got) != 0 {
		t.Fatalf("nothing may be stored after a failed insert, got %d", len(got))
	}
}
```
(`006_firewall_engine.sql:8` has `protocol VARCHAR(3) NOT NULL CHECK (protocol IN ('tcp', 'udp'))`.)

Add to `api/rest/firewall_engine_test.go`:

```go
func TestDuplicateForwardIsConflict(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	ctx := context.Background()
	net := &models.Network{Name: "fw-dup-test", CIDR: "10.21.0.0/24", InterfaceName: "wg92", ListenPort: 51992}
	if err := s.store.CreateNetwork(ctx, net); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), net.ID) })
	body := `{"protocol":"tcp","public_port":8082,"target_ip":"10.21.0.5","target_port":80}`
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/forwards?confirm=false", body); rec.Code != 200 {
		t.Fatalf("first forward = %d %s", rec.Code, rec.Body)
	}
	applied := len(r.applied)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/forwards?confirm=false", body); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate forward = %d, want 409", rec.Code)
	}
	if len(r.applied) != applied {
		t.Fatal("a duplicate must be refused before anything is applied")
	}
}

func TestEndpointForAddrPrefersLongestPrefix(t *testing.T) {
	peers := []wireguard.PeerStatus{
		{AllowedIPs: "0.0.0.0/0", Endpoint: "198.51.100.1:51820"},           // site gateway
		{AllowedIPs: "10.99.0.2/32, 10.99.1.0/24", Endpoint: "[::ffff:203.0.113.7]:40000"}, // operator
		{AllowedIPs: "10.99.0.0/24", Endpoint: "(none)"},
	}
	for i := 0; i < 3; i++ {
		ep, ok := endpointForAddr(peers, netip.MustParseAddr("10.99.0.2"))
		if !ok || ep != netip.MustParseAddr("203.0.113.7") {
			t.Fatalf("got %v %v, want the operator's own endpoint", ep, ok)
		}
		peers[0], peers[1] = peers[1], peers[0] // order must not matter
	}
	if _, ok := endpointForAddr(peers, netip.MustParseAddr("192.0.2.1")); !ok {
		t.Fatal("the gateway's 0.0.0.0/0 still matches unknown addresses")
	}
}

func TestV1ListShowsNetworkPortsAndShortIPv6(t *testing.T) {
	s, _ := newEngineServer(t, firewall.ModeNft)
	ctx := context.Background()
	net := &models.Network{Name: "fw-port-test", CIDR: "10.22.0.0/24", InterfaceName: "wg93", ListenPort: 51993}
	if err := s.store.CreateNetwork(ctx, net); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), net.ID) })
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", `{"ip":"2001:db8::9"}`); rec.Code != 200 {
		t.Fatalf("block = %d %s", rec.Code, rec.Body)
	}
	st := inputRules(t, s)
	var wg, v6 bool
	for _, c := range st.Chains {
		for _, rule := range c.Rules {
			wg = wg || (rule.Port == "51993" && rule.Protected)
			v6 = v6 || rule.Source == "2001:db8::9"
		}
	}
	if !wg || !v6 {
		t.Fatalf("network port shown=%v, IPv6 shown without /128=%v", wg, v6)
	}
}
```
(Add `"net/netip"` to the test imports. `wireguard` is already imported.)

- [ ] **Step 2: Run the tests and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure `undefined: endpointForAddr`, `CreateFirewallServices undefined`.

- [ ] **Step 3: Implement**

`store/firewall.go`: replace `CreateFirewallService` with a wrapper and add the transactional version.

```go
// CreateFirewallService stores a service; an empty ID gets a new UUID.
func (s *Store) CreateFirewallService(ctx context.Context, svc *models.FirewallService) error {
	return s.CreateFirewallServices(ctx, []*models.FirewallService{svc})
}

// CreateFirewallServices stores services in one transaction (Open Port with
// "both" creates a tcp and a udp service).
func (s *Store) CreateFirewallServices(ctx context.Context, svcs []*models.FirewallService) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	for _, svc := range svcs {
		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}
		if svc.Sources == nil {
			svc.Sources = []string{}
		}
		svc.CreatedAt = now
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_services (id, protocol, port_from, port_to, sources, interface, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			svc.ID, svc.Protocol, svc.PortFrom, svc.PortTo, pq.Array(svc.Sources),
			nullString(svc.Interface), nullString(svc.Comment), svc.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}
```

`firewall_v2_handlers.go`, `addServices` Commit:

```go
		Commit: func(ctx context.Context) error { return s.store.CreateFirewallServices(ctx, svcs) },
```

`firewall_v2_handlers.go`, `handleFirewallV2CreateForward` Mutate:

```go
		Mutate: func(st *firewall.State) error {
			for _, x := range st.Forwards {
				if x.Protocol == f.Protocol && x.PublicPort == f.PublicPort {
					return fmt.Errorf("%w: %s port %d is already forwarded", errConflict, f.Protocol, f.PublicPort)
				}
			}
			st.Forwards = append(st.Forwards, f)
			return nil
		},
```
(Add `"fmt"` to the imports if it is missing.)

`firewall_engine.go`:

```go
// errConflict is returned by engine mutations that collide with a stored record.
var errConflict = errors.New("conflict")
```
In `engineError`, add `errors.Is(err, errConflict),` to the 409 case.

Replace `wireGuardEndpointFor`:

```go
// wireGuardEndpointFor finds the public endpoint of the peer that owns addr.
func (s *Server) wireGuardEndpointFor(addr netip.Addr) (netip.Addr, bool) {
	s.managersMu.RLock()
	defer s.managersMu.RUnlock()
	var all []wireguard.PeerStatus
	for _, mgr := range s.managers {
		peers, err := mgr.GetPeers()
		if err != nil {
			continue
		}
		for _, p := range peers {
			all = append(all, p)
		}
	}
	return endpointForAddr(all, addr)
}

// endpointForAddr returns the endpoint of the peer whose AllowedIPs match
// addr most specifically, so a gateway with 0.0.0.0/0 never hides the
// operator's own peer.
func endpointForAddr(peers []wireguard.PeerStatus, addr netip.Addr) (netip.Addr, bool) {
	best, bestBits := netip.Addr{}, -1
	for _, p := range peers {
		ap, err := netip.ParseAddrPort(p.Endpoint)
		if err != nil {
			continue
		}
		for _, allowed := range strings.Split(p.AllowedIPs, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(allowed))
			if err != nil || !prefix.Contains(addr) || prefix.Bits() <= bestBits {
				continue
			}
			best, bestBits = ap.Addr().Unmap(), prefix.Bits()
		}
	}
	return best, bestBits >= 0
}
```

`firewall_v1_nft.go`: add the helper and use it in both places that call `strings.TrimSuffix(..., "/32")`, at lines 84 and 313:

```go
// displayPrefix shows single addresses without their /32 or /128.
func displayPrefix(p string) string {
	return strings.TrimSuffix(strings.TrimSuffix(p, "/32"), "/128")
}
```

In `v1Entries`, directly after the `51820:51900` WireGuard entry:

```go
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range networks {
		if n.ListenPort > 0 && (n.ListenPort < int(nft.LegacyWireGuardRange.From) || n.ListenPort > int(nft.LegacyWireGuardRange.To)) {
			add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "udp", Port: strconv.Itoa(n.ListenPort),
				Options: "WireGuard " + n.InterfaceName, Protected: true}})
		}
	}
```
Check the type of `models.Network.ListenPort`. If it is not `int`, convert it the same way the existing code in `firewall/build.go` does.

`web/src/api/client.ts`: the backend registers only `POST /firewall/host/rules/delete` (`handlers.go:330`), so:

```ts
  async deleteFirewallRule(request: DeleteRuleRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/rules/delete', request)
    return data
  }
```
(Keep the existing `return` line as it is.)

- [ ] **Step 4: Run the tests and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`.

Frontend type check: `MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/web:/w -w /w node:20-bookworm sh -c "npm ci --silent && npx tsc --noEmit"`. Expected: exit 0. If the project has no `tsconfig` check script, record the exact output instead.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/store/firewall.go server/internal/controlplane/store/firewall_test.go server/internal/controlplane/api/rest/firewall_v2_handlers.go server/internal/controlplane/api/rest/firewall_engine.go server/internal/controlplane/api/rest/firewall_v1_nft.go server/internal/controlplane/api/rest/firewall_engine_test.go web/src/api/client.ts
git commit -m "fix: close firewall review gaps in forwards, services and v1 view"
```

---

### Task 4: Legacy iptables path protects every detected SSH port

In iptables mode, Close Port and Delete protect only port 22. If sshd listens on 2222, the panel can close it and lock the operator out.

**Files:**
- Modify: `server/internal/controlplane/api/rest/firewall_handlers.go` (lines 87-112 `protectedPorts`/`isProtectedRule`, line 169, line 416)
- Modify: `server/internal/controlplane/api/rest/firewall_portmatch_test.go`

**Interfaces:**
- Consumes: `nft.DetectSSHPorts(nft.Runner) ([]uint16, error)`, `nft.HostRunner`.
- Produces: `var legacySSHPorts func() []uint16` and `isProtectedRule(rule FirewallRule, sshPorts []uint16) bool`.

- [ ] **Step 1: Write the failing tests** (append to `firewall_portmatch_test.go`)

```go
func TestCustomSSHPortIsProtectedInLegacyMode(t *testing.T) {
	orig := legacySSHPorts
	legacySSHPorts = func() []uint16 { return []uint16{22, 2222} }
	t.Cleanup(func() { legacySSHPorts = orig })

	if !isProtectedRule(FirewallRule{Port: "2222", Target: "ACCEPT"}, legacySSHPorts()) {
		t.Fatal("an ACCEPT for a detected SSH port must be protected")
	}
	if isProtectedRule(FirewallRule{Port: "2223", Target: "ACCEPT"}, legacySSHPorts()) {
		t.Fatal("other ports are not SSH")
	}

	s := &Server{}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"port":2222,"protocol":"tcp"}`))
	rec := httptest.NewRecorder()
	s.handleFirewallClosePort(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("closing a detected SSH port = %d, want 403", rec.Code)
	}
}
```
(Add `net/http`, `net/http/httptest` and `strings` to the imports if the file lacks them. `s.firewall` is nil, so `engineEnforces()` is false and the handler returns before any host command.)

- [ ] **Step 2: Run the tests and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure `undefined: legacySSHPorts` / `too many arguments in call to isProtectedRule`.

- [ ] **Step 3: Implement**

```go
// legacySSHPorts returns the ports sshd uses, so the iptables code paths
// never close SSH on a custom port; 22 alone when detection fails, as before
// (replaced in tests).
var legacySSHPorts = func() []uint16 {
	ports, err := nft.DetectSSHPorts(nft.HostRunner{})
	if err != nil {
		return []uint16{22}
	}
	return ports
}

func isSSHPort(port string, sshPorts []uint16) bool {
	for _, p := range sshPorts {
		if port == strconv.Itoa(int(p)) {
			return true
		}
	}
	return false
}
```

In `isProtectedRule`, change the signature to `func isProtectedRule(rule FirewallRule, sshPorts []uint16) bool` and replace `if rule.Port == "22" && rule.Target == "ACCEPT"` with `if isSSHPort(rule.Port, sshPorts) && rule.Target == "ACCEPT"`.

In `parseIptablesOutput`, compute `sshPorts := legacySSHPorts()` once before the line loop and call `isProtectedRule(*rule, sshPorts)`. Before editing, run `grep -n "isProtectedRule(" server/internal` and update every call site.

In `handleFirewallClosePort`, directly after the existing `protectedPorts` check:

```go
	if isSSHPort(strconv.Itoa(req.Port), legacySSHPorts()) && !req.Force {
		errorResponse(w, http.StatusForbidden, fmt.Sprintf("port %d (SSH) is protected. Set force=true to override", req.Port))
		return
	}
```
Add the import `"github.com/novusgate/novusgate/internal/netctl/nft"` if the file lacks it.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`, including `TestFindRuleLineNumber` (unchanged).

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest/firewall_handlers.go server/internal/controlplane/api/rest/firewall_portmatch_test.go
git commit -m "fix: protect custom SSH ports in the iptables firewall paths"
```

---

### Task 5: Admin exception per real network interfaces (M5) and edge rulesets across nft versions (M10)

**Files:**
- Modify: `server/internal/netctl/nft/compile.go:83`, `server/internal/netctl/nft/validate.go:64,159-161`
- Modify: `server/internal/netctl/nft/compile_test.go` (line 88 expectation; new tests)
- Modify: `server/internal/netctl/nft/testdata/full.nft` (regenerated)
- Create: `server/internal/netctl/nft/testdata/empty.nft`, `server/internal/netctl/nft/testdata/v6only.nft`
- Create: `server/scripts/nft-versions-check.sh`, `server/scripts/nft-versions-inner.sh`

**Interfaces:**
- Produces: `vpnInterfaces(rs Ruleset) []string` (sorted, unique, always contains `AdminInterface`). `isVPNInterface` is removed: its only caller (`validate.go:64`) now uses `vpnInterfaces`.

- [ ] **Step 1: Write the failing tests** (`compile_test.go`)

Change the expectation at line 88 to:

```go
		`iifname { "wg0", "wg1", "wg2" } tcp dport { 8080, 8443 } accept`,
```

Append:

```go
// M5: only interfaces of real NovusGate networks may reach the API ports or
// open reserved ports; "wg-foo" from another tool is public.
func TestReservedPortsOnlyOnNetworkInterfaces(t *testing.T) {
	rs := fullRuleset()
	rs.Services = append(rs.Services, Service{ID: "foreign-wg", Proto: TCP, Ports: PortRange{8080, 8080}, Interface: "wg9"})
	if _, err := Compile(rs, testNow); err == nil {
		t.Fatal("a reserved port on an interface that is not a NovusGate network must be rejected")
	}
}

func edgeRulesets() map[string]Ruleset {
	return map[string]Ruleset{
		"empty": {SSHPorts: []uint16{22}, EgressInterface: "eth0"},
		"v6only": {
			SSHPorts: []uint16{22}, EgressInterface: "eth0",
			Services: []Service{{ID: "v6-https", Proto: TCP, Ports: PortRange{443, 443},
				Sources: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}},
			Blocked: []BlockedEntry{{Prefix: netip.MustParsePrefix("2001:db8:bad::/48")}},
		},
	}
}

func TestCompileEdgeGoldens(t *testing.T) {
	for name, rs := range edgeRulesets() {
		got, err := Compile(rs, testNow)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		path := filepath.Join("testdata", name+".nft")
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test -update once)", name, err)
		}
		if got != string(want) {
			t.Errorf("%s: golden mismatch\n%s", name, got)
		}
		if os.Getenv("NFT_CHECK") == "1" {
			cmd := exec.Command("nft", "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(got)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s: nft -c rejected: %v\n%s", name, err, out)
			}
		}
	}
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: FAIL. The line-88 expectation is not found, `TestReservedPortsOnlyOnNetworkInterfaces` gets no error, and the edge goldens are missing.

- [ ] **Step 3: Implement**

`compile.go`: replace the API-ports line (83):

```go
	b.line(2, fmt.Sprintf(`iifname { %s } tcp dport { %s } accept`, quoteJoin(vpnInterfaces(rs)), joinPorts(APIPorts)))
```
and add:

```go
// vpnInterfaces lists the WireGuard interfaces of NovusGate's networks plus
// the admin interface, sorted, so only real VPN networks get the VPN-only
// exceptions (M5).
func vpnInterfaces(rs Ruleset) []string {
	seen := map[string]bool{AdminInterface: true}
	out := []string{AdminInterface}
	for _, n := range rs.Networks {
		if !seen[n.Interface] {
			seen[n.Interface] = true
			out = append(out, n.Interface)
		}
	}
	sort.Strings(out)
	return out
}

func quoteJoin(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = strconv.Quote(n)
	}
	return strings.Join(q, ", ")
}
```
(Add `sort`/`strconv`/`strings` to the imports only if they are missing. Network interface names already pass `ValidInterfaceName`, so `strconv.Quote` output equals nft's `"name"`.)

`validate.go:64`: replace `if s.Proto == TCP && !isVPNInterface(s.Interface) {` with:

```go
		if s.Proto == TCP && !containsString(vpnInterfaces(rs), s.Interface) {
```
Delete `isVPNInterface` (lines 159-161) and add:

```go
func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
```
Before deleting, run `grep -rn "isVPNInterface" server/internal` and confirm that the only caller is line 64.

Regenerate the goldens once with `-update`. Because of the shim rule, put the command in a script file in the scratchpad instead of the repo: `<scratchpad>/golden.sh` containing `cd /src && go test ./internal/netctl/nft/ -run 'TestCompileGolden|TestCompileEdgeGoldens' -update -count=1`. Then run:

`MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -v <scratchpad-as-/mnt/c-path>:/s golang:1.23 bash /s/golden.sh`

Afterwards, run `git diff server/internal/netctl/nft/testdata/full.nft`. Expected: only the API-ports line changed.

Cross-version check (M10). `server/scripts/nft-versions-check.sh`:

```bash
#!/bin/bash
# Validates the golden rulesets with the nft parser of every supported host
# (Ubuntu 22.04 = 1.0.2, Debian bookworm = 1.0.6, Ubuntu 24.04 = 1.0.9) and
# checks that a snapshot listed by nft 1.0.9 (the control plane) loads with
# each of them (the host-side rollback and boot unit). NET_ADMIN only; each
# container uses its own network namespace. Run from Git Bash:
#   bash server/scripts/nft-versions-check.sh
set -euo pipefail
SERVER_DIR="${SERVER_DIR:-/mnt/c/Users/Administrator/Desktop/NovusGate/server}"
VOL=novusgate-nft-check
docker volume rm "$VOL" > /dev/null 2>&1 || true
docker volume create "$VOL" > /dev/null
trap 'docker volume rm "$VOL" > /dev/null 2>&1 || true' EXIT
run() {
  MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v "$SERVER_DIR":/src:ro -v "$VOL":/out \
    -e STEP="$2" "$1" bash /src/scripts/nft-versions-inner.sh
}
run ubuntu:24.04 snapshot
for img in ubuntu:22.04 debian:bookworm ubuntu:24.04; do
  run "$img" check
done
echo "NFT-VERSIONS-OK"
```

`server/scripts/nft-versions-inner.sh`:

```bash
#!/bin/bash
# Runs inside a distro container for nft-versions-check.sh.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null
apt-get install -y -qq nftables > /dev/null
echo "== $(. /etc/os-release && echo "$PRETTY_NAME"): $(nft --version)"
cd /src/internal/netctl/nft/testdata
case "$STEP" in
  snapshot)
    nft -f full.nft
    nft list table inet novusgate > /out/snapshot.nft
    ;;
  check)
    for f in *.nft; do
      nft -c -f "$f"
      echo "ok $f"
    done
    { echo "table inet novusgate"; echo "delete table inet novusgate"; cat /out/snapshot.nft; } > /tmp/restore.nft
    nft -c -f /tmp/restore.nft
    echo "ok snapshot from nft 1.0.9"
    ;;
esac
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok` (the edge goldens pass `nft -c` inside the test image).

Run: `bash server/scripts/nft-versions-check.sh`
Expected: three `== …` headers, `ok full.nft`, `ok empty.nft`, `ok v6only.nft` and `ok snapshot from nft 1.0.9` for each image, then `NFT-VERSIONS-OK`. If an image rejects a file, this task is not done: report the exact nft error and stop (3-strike rule).

- [ ] **Step 5: Commit**

```bash
git add server/internal/netctl/nft/compile.go server/internal/netctl/nft/validate.go server/internal/netctl/nft/compile_test.go server/internal/netctl/nft/testdata server/scripts/nft-versions-check.sh server/scripts/nft-versions-inner.sh
git commit -m "fix: limit VPN-only exceptions to network interfaces"
```

---

### Task 6: `setup-firewall.sh` — nftables, boot unit, fail2ban, nft-mode skip, iptables revert

**Files:**
- Modify: `server/deployments/docker/setup-firewall.sh`
- Modify: `server/deployments/docker/tests/setup-firewall_test.sh`

**Interfaces:**
- Consumes:
  - `/etc/novusgate/firewall.nft` (`firewall.PersistPath`);
  - unit name `novusgate-firewall.service` (`firewall.BootUnit`, Task 2);
  - the `.env` key `FIREWALL_ENGINE` (compose, P3b-1).
- Produces these shell functions:
  - `firewall_engine` prints `iptables|shadow|nft`;
  - `install_nftables`;
  - `install_boot_unit`;
  - `configure_fail2ban <engine>`;
  - `remove_nft_engine`.

  Test overrides: `ENV_FILE`, `NFT_RULESET`, `UNIT_DIR` and `F2B_JAIL_DIR`.

- [ ] **Step 1: Write the failing tests** (append before the final `FAILURES` check in `setup-firewall_test.sh`)

```bash
# --- P3b-2: engine-aware main ---
# run_main <FIREWALL_ENGINE or ""> <create ruleset: yes|no> <nft has table: yes|no>
# Prints the stub dir; calls.log has every host command in order.
run_main() {
  local engine="$1" ruleset="$2" has_table="$3" stub
  stub="$(mktemp -d)"
  mkdir -p "$stub/units" "$stub/jail.d"
  for cmd in iptables nft systemctl apt-get netfilter-persistent docker-compose sleep debconf-set-selections; do
    printf '#!/bin/bash\necho "%s $*" >> "%s/calls.log"\n' "$cmd" "$stub" > "$stub/$cmd"
    chmod +x "$stub/$cmd"
  done
  if [ "$has_table" = "yes" ]; then
    printf '#!/bin/bash\necho "nft $*" >> "%s/calls.log"\nexit 0\n' "$stub" > "$stub/nft"
  else
    printf '#!/bin/bash\necho "nft $*" >> "%s/calls.log"\n[ "$1" = "list" ] && exit 1\nexit 0\n' "$stub" > "$stub/nft"
  fi
  chmod +x "$stub/nft"
  printf '#!/bin/bash\necho "ii  iptables-persistent"\n' > "$stub/dpkg"
  chmod +x "$stub/dpkg"
  printf 'port 22\nport 2222\n' > "$stub/sshd.out"
  printf '#!/bin/bash\ncat "%s/sshd.out"\n' "$stub" > "$stub/sshd"
  chmod +x "$stub/sshd"
  [ -n "$engine" ] && printf 'POSTGRES_PASSWORD=x\nFIREWALL_ENGINE=%s\n' "$engine" > "$stub/.env"
  [ "$ruleset" = "yes" ] && echo "table inet novusgate {}" > "$stub/firewall.nft"
  (
    export PATH="$stub:/usr/bin:/bin"
    export ENV_FILE="$stub/.env" NFT_RULESET="$stub/firewall.nft" UNIT_DIR="$stub/units" F2B_JAIL_DIR="$stub/jail.d"
    unset SSH_PORT SSH_CONNECTION
    # shellcheck source=../setup-firewall.sh
    source "$SCRIPT"
    main > /dev/null
  )
  echo "$stub"
}

assert_has() { grep -q -F -- "$2" "$1" || fail "$3: missing '$2'"; }
assert_not() { if grep -q -F -- "$2" "$1"; then fail "$3: unexpected '$2'"; fi; }

# Case 6: default (no FIREWALL_ENGINE) = iptables mode; reverts a leftover nft engine after DROP
d="$(run_main "" yes yes)"
assert_has "$d/calls.log" "iptables -P INPUT DROP" "iptables mode"
assert_has "$d/calls.log" "nft delete table inet novusgate" "iptables mode reverts"
drop_at="$(grep -n -F "iptables -P INPUT DROP" "$d/calls.log" | cut -d: -f1)"
del_at="$(grep -n -F "nft delete table inet novusgate" "$d/calls.log" | cut -d: -f1)"
[ "$drop_at" -lt "$del_at" ] || fail "iptables mode: the nft table must be removed only after INPUT DROP is back"
[ ! -f "$d/firewall.nft" ] || fail "iptables mode: the boot ruleset must be removed"
assert_has "$d/calls.log" "systemctl restart docker" "iptables mode"
assert_has "$d/jail.d/novusgate.local" "port = 22,2222" "fail2ban ports"
assert_not "$d/jail.d/novusgate.local" "banaction" "iptables mode fail2ban"

# Case 7: nft mode with a ruleset = control plane owns INPUT; iptables and Docker untouched
d="$(run_main nft yes yes)"
assert_not "$d/calls.log" "iptables " "nft mode"
assert_not "$d/calls.log" "systemctl restart docker" "nft mode"
assert_not "$d/calls.log" "nft delete table" "nft mode"
assert_has "$d/jail.d/novusgate.local" "banaction = nftables-multiport" "nft mode fail2ban"
assert_has "$d/jail.d/novusgate.local" "port = 22,2222" "nft mode fail2ban"

# Case 8: nft mode before the first apply = iptables baseline stays (control plane hands over later)
d="$(run_main nft no no)"
assert_has "$d/calls.log" "iptables -P INPUT DROP" "nft mode, no ruleset yet"
assert_not "$d/calls.log" "nft delete table" "nft mode, no ruleset yet"

# Case 9: boot unit and nftables in every mode; nftables.service is never enabled
for mode in "" nft; do
  d="$(run_main "$mode" yes yes)"
  unit="$d/units/novusgate-firewall.service"
  [ -f "$unit" ] || { fail "boot unit missing ($mode)"; continue; }
  assert_has "$unit" "ConditionPathExists=$d/firewall.nft" "boot unit"
  assert_has "$unit" "Before=network-pre.target docker.service" "boot unit"
  assert_has "$unit" "ExecStart=/usr/sbin/nft -f $d/firewall.nft" "boot unit"
  assert_has "$d/calls.log" "systemctl enable novusgate-firewall.service" "boot unit"
  assert_not "$d/calls.log" "enable nftables" "boot unit"
done

# Case 10: nft missing -> installed
d="$(mktemp -d)"
# (covered by install_nftables: when `command -v nft` fails, apt-get install nftables runs)
(
  export PATH="$d:/usr/bin:/bin"
  printf '#!/bin/bash\necho "apt-get $*" >> "%s/calls.log"\n' "$d" > "$d/apt-get"; chmod +x "$d/apt-get"
  source "$SCRIPT"
  install_nftables > /dev/null
)
assert_has "$d/calls.log" "apt-get install -y nftables" "install_nftables"
```

Note for Case 10: the ubuntu:24.04 test image has no `nft` in `/usr/bin`, so `command -v nft` fails there. If the image ever ships one, put `nft` in neither directory by using `PATH="$d"` plus absolute paths. Do not change the assertion.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/deployments/docker:/w -w /w ubuntu:24.04 bash tests/setup-firewall_test.sh`
Expected: `FAIL` lines for cases 6–10 (`main` ignores the engine, there is no unit and no jail) and a non-zero exit.

- [ ] **Step 3: Implement in `setup-firewall.sh`**

Add after `set -e`:

```bash
ENV_FILE="${ENV_FILE:-/opt/NovusGate/server/deployments/docker/.env}"
NFT_RULESET="${NFT_RULESET:-/etc/novusgate/firewall.nft}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
F2B_JAIL_DIR="${F2B_JAIL_DIR:-/etc/fail2ban/jail.d}"
BOOT_UNIT=novusgate-firewall.service
```

Add the functions after `detect_ssh_ports`:

```bash
# firewall_engine prints FIREWALL_ENGINE from the compose .env (iptables when unset).
firewall_engine() {
  local v=""
  if [ -f "$ENV_FILE" ]; then
    v="$(grep -E '^FIREWALL_ENGINE=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d "\"' \r" | tr '[:upper:]' '[:lower:]')"
  fi
  echo "${v:-iptables}"
}

# install_nftables installs the nft CLI the boot unit and the control plane's
# host-side rollback need. nftables.service is never enabled: its default
# config flushes the whole ruleset, including Docker's.
install_nftables() {
  if ! command -v nft > /dev/null 2>&1; then
    echo "[FIREWALL] Installing nftables..."
    apt-get update -qq
    apt-get install -y nftables
  fi
}

# install_boot_unit loads the control plane's ruleset before Docker on every
# boot; without the ruleset file (iptables mode) it does nothing.
install_boot_unit() {
  cat > "$UNIT_DIR/$BOOT_UNIT" <<UNIT
[Unit]
Description=NovusGate nftables firewall (table inet novusgate)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target docker.service
After=local-fs.target
ConditionPathExists=$NFT_RULESET

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $NFT_RULESET

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$BOOT_UNIT"
}

# configure_fail2ban makes the sshd jail cover every SSH port and, in nft
# mode, ban through nftables instead of iptables.
configure_fail2ban() {
  local engine="$1" ports
  [ -d "$F2B_JAIL_DIR" ] || return 0
  ports="$(detect_ssh_ports | paste -sd, -)"
  {
    echo "# Managed by NovusGate setup-firewall.sh"
    echo "[sshd]"
    echo "port = $ports"
    if [ "$engine" = "nft" ]; then
      echo "banaction = nftables-multiport"
      echo "banaction_allports = nftables-allports"
    fi
  } > "$F2B_JAIL_DIR/novusgate.local"
  if systemctl is-active --quiet fail2ban 2> /dev/null; then
    systemctl reload fail2ban || echo "[FIREWALL] Warning: fail2ban reload failed; check 'fail2ban-client status'"
  fi
}

# remove_nft_engine undoes FIREWALL_ENGINE=nft; call it only after the
# iptables baseline (INPUT DROP) is back.
remove_nft_engine() {
  if nft list table inet novusgate > /dev/null 2>&1; then
    echo "[FIREWALL] Removing table inet novusgate (FIREWALL_ENGINE is not nft)..."
    nft delete table inet novusgate
  fi
  rm -f "$NFT_RULESET"
}
```

Replace `main`:

```bash
main() {
  local engine
  engine="$(firewall_engine)"
  echo "[FIREWALL] Engine: $engine"
  install_nftables
  install_boot_unit
  configure_fail2ban "$engine"
  if [ "$engine" = "nft" ] && [ -f "$NFT_RULESET" ]; then
    echo "[FIREWALL] FIREWALL_ENGINE=nft: the control plane owns INPUT filtering; iptables and Docker are left unchanged."
    return 0
  fi
  echo "[FIREWALL] Configuring iptables rules..."
  install_persistence
  apply_rules
  if [ "$engine" != "nft" ]; then
    remove_nft_engine
  fi
  echo "[FIREWALL] Saving rules..."
  netfilter-persistent save
  restart_docker_stack
  echo "[FIREWALL] Done! Admin ports are now secured behind VPN."
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/deployments/docker:/w -w /w ubuntu:24.04 bash tests/setup-firewall_test.sh`
Expected: `OK`, exit 0. The old cases 1–5 must still pass.

Also run `bash -n server/deployments/docker/setup-firewall.sh` (syntax only). Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add server/deployments/docker/setup-firewall.sh server/deployments/docker/tests/setup-firewall_test.sh
git commit -m "feat: make setup-firewall.sh nftables-aware with boot unit"
```

---

### Task 7: Documentation and staging runbook

**Files:**
- Create: `docs/runbooks/p3b2-firewall-cutover.md`
- Modify: `docs/api.md`, `docs/architecture.md`, `docs/active-context.md`, `docs/superpowers/specs/2026-10-13-p3-firewall-design.md` (§6a and §6b: mark closed items with their commit; status line)

- [ ] **Step 1: Write the runbook** (`docs/runbooks/p3b2-firewall-cutover.md`, Azerbaijani, every step with the exact command and the expected output; results are appended at the end of the file, never invented)

Required steps, in this order:
1. Staging: Ubuntu 24.04 VM that passed the P1 and P3b-1 runbooks. `sshd` listens on 22 **and 2222** (`Port 22`, `Port 2222` in `/etc/ssh/sshd_config`, `systemctl restart ssh`).
2. Run Center → Update (runs `setup-firewall.sh`). Checks:
   - `systemctl is-enabled novusgate-firewall.service` → `enabled`;
   - `nft --version` ≥ 1.0.2;
   - `systemctl is-enabled nftables` → `disabled`;
   - `cat /etc/fail2ban/jail.d/novusgate.local` → `port = 22,2222`.
3. Write `FIREWALL_ENGINE=nft` to `.env`, then `docker compose up -d control-plane`. Expected log lines:
   - `imported N panel rules`;
   - `nftables engine applied`;
   - `iptables INPUT handed over to nftables (N rules removed)`.

   Then:
   - `iptables -S INPUT` → `-P INPUT ACCEPT` plus only `f2b-*` jumps;
   - `iptables -S FORWARD | grep novusgate-vpn` → empty.
4. From outside: panel → Open Port 8444 → `nc -zv <server> 8444` reaches a listener (`python3 -m http.server 8444` on the host). Close Port 8444 → connection refused/timeout.
5. Lockout scenarios: Block your own public IP → 400. Close Port 2222 → 403. A v2 change without confirm → after 75 s it is rolled back and you can still SSH in.
6. Re-run Center → Update (server changed) → `iptables -S INPUT` is unchanged (still ACCEPT, no rebuild) and Docker was not restarted (`docker ps` uptime).
7. `reboot`. After boot:
   - `systemctl status novusgate-firewall.service` → `active (exited)`;
   - `nft list table inet novusgate` exists before the control plane starts (`journalctl -b -u novusgate-firewall -u docker` order);
   - SSH on 22 and 2222 works;
   - the panel works over VPN;
   - port 8444 behaves as before the reboot.
8. fail2ban: 4 wrong SSH passwords from a test IP on port 2222 → `fail2ban-client status sshd` lists the IP, and `nft list ruleset | grep -A3 f2b` shows it.
9. **M8 note:** containers on the user's own Docker bridge networks cannot reach host services or VPN peers (input policy drop, forward to `wg*` only DNAT). Verify with `docker run --rm alpine wget -T3 http://<vpn-ip>:8080` → fails. This is expected and documented.
10. Revert:
    - `FIREWALL_ENGINE=iptables` in `.env`, `docker compose up -d control-plane`, then `bash /opt/NovusGate/server/deployments/docker/setup-firewall.sh`;
    - `iptables -S INPUT` → the installer baseline with `-P INPUT DROP`;
    - `nft list tables` → no `novusgate`;
    - `ls /etc/novusgate/firewall.nft` → missing;
    - `curl -X POST …/api/v1/firewall/vpn/apply` → the `novusgate-vpn-*` FORWARD rules are back;
    - SSH on 22 and 2222 works.
11. Unsupported host (optional, Ubuntu 20.04 VM): `FIREWALL_ENGINE=nft` → log `host not ready for FIREWALL_ENGINE=nft … older than 1.0.2` or `… not on the nf_tables backend`, `nft list tables` → no `novusgate`, and the panel's Open Port → 409.

- [ ] **Step 2: Update the reference docs**
  - `docs/api.md`, "Status kodları":
    - 409 also covers `firewall engine is starting` and a duplicate forward (`… is already forwarded`).
    - Under "Köhnə firewall endpoint-ləri", add the sentence: "In iptables mode, Close Port and Delete also protect every detected SSH port (403)."
  - `docs/architecture.md`, "Firewall engine inteqrasiyası": add these bullets:
    - **Host check:** `CheckHost` requires nft ≥ 1.0.2, `novusgate-firewall.service` enabled and the nf_tables backend.
    - **Hand-over:** `CutoverIptables` sets INPUT to ACCEPT, deletes the panel and installer rules except `f2b-*`, and runs `netfilter-persistent save`. It runs once per start, after the first apply.
    - **Readiness:** `ErrNotReady` until the import is done.
    - **Boot:** `novusgate-firewall.service` (`setup-firewall.sh`, before `network-pre`/`docker`).
    - **setup-firewall.sh:** in nft mode it leaves iptables alone; in iptables mode it removes the nft engine.
    - **M5:** VPN-only exceptions apply only to network interfaces.

    Remove the sentence "Onu yükləyən unit P3b-2-dədir."
  - P3 spec:
    - §6a: mark M5, M8, M10 and the installer `nftables` item as closed (commit hashes).
    - §6b: mark items 1, 2, 3, 5 (WireGuard ports, `/128`), 6 and 7 as closed. Item 4 stays as the user's decision. The `line_number` drift in item 5 stays as a known limitation of the v1 view.
  - Mark `docs/runbooks/p3b1-firewall-engine.md` as superseded by the P3b-2 runbook at the top. Keep the file.
  - `docs/active-context.md`: a new session block plus rows in the "Son Dəyişikliklər" table.

- [ ] **Step 3: Verify**

Run: `bash server/scripts/test-with-postgres.sh` and the setup-firewall test command from Task 6.
Expected: all `ok` / `OK` (docs-only step; this confirms nothing regressed since Task 6).

- [ ] **Step 4: Commit**

```bash
git add docs/runbooks/p3b2-firewall-cutover.md docs/runbooks/p3b1-firewall-engine.md docs/api.md docs/architecture.md docs/active-context.md docs/superpowers/specs/2026-10-13-p3-firewall-design.md
git commit -m "docs: document P3b-2 firewall cutover and staging runbook"
```

---

## Out of scope (stays open)

- **§6b.4:** a whole-address Allow IP opens the admin ports for public sources (legacy parity). This is the user's decision.
- The `line_number` drift in the v1 view when an expiry or a change of SSH ports happens between list and delete. This is inherent to the number-based v1 API, and the P3c UI uses v2 IDs.
- ip6tables INPUT is not touched. The installer never configured it, and nftables now enforces IPv6.
- Real-host verification: staging runbook (Task 7). No privileged containers.
