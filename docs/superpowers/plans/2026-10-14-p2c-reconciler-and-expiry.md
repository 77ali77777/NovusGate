# P2c WireGuard Reconciler and Node Expiry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the database the source of truth for WireGuard peers and close B11. Expired nodes lose their peer within one tick even when nobody opens the panel. Re-activated nodes get their peer back. A reconciler compares DB and kernel every 15 s: in `shadow` mode it only logs the difference, in `enforce` mode it applies it.

**Architecture:**
- A new `internal/controlplane/reconciler` package works through two narrow interfaces: `PeerControl` (satisfied by the existing `wireguard.Manager`) and `Store` (satisfied by `*store.Store`). That makes all logic testable with fakes.
- One goroutine ticks every 15 s, and handlers can also trigger it. Each tick runs two steps:
  1. The **expire step** persists `expired` in the DB and removes those nodes' peers. It runs in shadow and enforce: this is today's lazy expiry, done on time.
  2. The **diff step** plans add/update/remove. It is logged in shadow and applied in enforce, with a DB re-check before each change.
- Unknown peers (not in the DB) are reported, never removed (adopt, master spec §3.4).

**Tech Stack:** Go 1.23 standard library, `wg` CLI through the existing `wireguard.Manager`, PostgreSQL 16 (tests).

**Spec:** `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md` §1 (P2c row) and §2.4 (adopt). It elaborates master spec `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` §3.3 (shadow first, env-selected mode), §3.4 (adopt), §4.1 (reconciler every 15 s and after writes; only active nodes are peers), §5 (P2 acceptance: "expiry panel bağlı olanda da işləyir") and §7 B11.

## Global Constraints

- **No new Go modules.** `wgctrl` is not added (P2 spec §2.2).
- **`WG_RECONCILER` = `off` | `shadow` | `enforce`.**
  - The default is `shadow`, and compose passes `${WG_RECONCILER:-shadow}`.
  - An unknown value stops startup, the same way an invalid `FIREWALL_ENGINE` does: a typo must not silently pick a mode.
  - `off` restores today's behaviour exactly (no goroutine).
- **Shadow mode never changes a peer through the diff step.** Only the expire step removes peers, and only of nodes whose `expires_at` has passed. Today `enrichNode` already removes those on the next panel read.
- **Unknown peers are never removed** in any mode.
- **Enforce never shrinks a peer's allowed-ips:** an update only adds the node's `/32` to the existing list.
- **Out of scope here:** writing `[Peer]` sections into `wgN.conf` (spec §4.1) is **deferred to P2c-2**. `wg0.conf` is written by the host installer and is the bootstrap key source (`main.go` `bootstrapSystem`), and P1's `restorePeers` already restores peers after a restart. Docs record this.
- **API contract:**
  - `/health` gains `checks.reconciler` only when a reconciler runs, so the contract snapshot (no reconciler) is unchanged.
  - `PUT /nodes/{id}` keeps its response shape.
- **Environment:**
  - Go runs only in Docker: `bash server/scripts/test-with-postgres.sh`.
  - Contract snapshots: `bash server/scripts/update-contracts.sh`.
  - The WSL shim expands `$`/`|`, so logic goes in script files.
  - No `--privileged`.
  - Tests never touch the host's WireGuard: use the fakes and seams.
- Logs go through `log/slog`, at the level the message deserves (`TestLogLevelsMatchMessages`).
- Commits carry no `Co-Authored-By`/"Claude"/"Anthropic"/"AI generated" lines. Comments in English, docs in Azerbaijani with full diacritics.

## Review Focus

1. **A node is deleted (or expires) between the reconciler's plan and its apply in enforce mode.**
   - Expected: the reconciler must not re-add the peer, because a resurrected peer of a deleted node would then sit there as "unknown" forever.
   - Pinned by Task 3 `TestEnforceRechecksBeforeApplying`.
2. **One interface is down or `wg show` fails.**
   - Expected: that interface is reported as an error and skipped, the other interfaces are still reconciled, and the loop keeps running.
   - Pinned by Task 3 `TestOneBrokenInterfaceDoesNotStopTheOthers`.
3. **A site gateway peer whose allowed-ips carries extra routes.**
   - Expected: enforce never removes them.
   - Pinned by Task 3 `TestEnforceNeverShrinksAllowedIPs`.
4. **Extending `expires_at` of a node the panel already showed as expired** (DB status still `online`, peer removed lazily).
   - Expected: the peer comes back right away.
   - Pinned by Task 1 `TestPeerTransition` and Task 2 `TestExpireNodesPersistsOnce`.
5. **Shutdown while a tick runs, or many triggers at once.**
   - Expected: the loop stops on context cancel, and triggers coalesce (no unbounded goroutines or queued runs).
   - Pinned by Task 4 `TestRunLoopTriggersCoalesceAndStop`.

---

## File Structure

| File | Responsibility |
|---|---|
| `server/internal/shared/models/models.go` (modify) | `(*Node).Active(now) bool` |
| `server/internal/shared/models/node_test.go` (create) | `Active` tests |
| `server/internal/controlplane/api/rest/peer_restore.go` (modify) | use `Active`; delete `isNodeActive` |
| `server/internal/controlplane/api/rest/node_transition.go` (create) + `_test.go` | `peerTransition(before, after, now) (add, remove bool)` |
| `server/internal/controlplane/api/rest/handlers.go` (modify) | `handleUpdateNode` uses `peerTransition`; triggers; health; `handleCreateNetwork` single `Up` |
| `server/internal/controlplane/api/rest/firewall_handlers.go` (modify) | `syncPeerAllowedIPs` skips inactive nodes |
| `server/internal/controlplane/store/store.go` (modify) + `store/expire_test.go` (create) | `ExpireNodes` |
| `server/internal/controlplane/reconciler/reconciler.go`, `plan.go`, `reconciler_test.go` (create) | the reconciler |
| `server/internal/controlplane/api/rest/reconciler_wiring.go` (create) | `SetReconciler`, `triggerReconcile` |
| `server/cmd/control-plane/main.go` (modify), `server/deployments/docker/docker-compose.yml` (modify) | wiring and env |
| `server/internal/shared/logging/noprint_test.go` (modify) | walk all of `internal/` and resolve import aliases (P2b deferred minor #5) |
| `docs/*` | docs |

---

### Task 1: One definition of "active", and B11 in the handlers

**Files:**
- Modify: `server/internal/shared/models/models.go`; create `server/internal/shared/models/node_test.go`
- Modify: `server/internal/controlplane/api/rest/peer_restore.go` (remove `isNodeActive`; callers use `node.Active(now)`)
- Create: `server/internal/controlplane/api/rest/node_transition.go`, `server/internal/controlplane/api/rest/node_transition_test.go`
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`handleUpdateNode`, the status/expiry block)
- Modify: `server/internal/controlplane/api/rest/firewall_handlers.go` (`syncPeerAllowedIPs`, the `for _, node := range nodes` loop)

**Interfaces:**
- Produces:
  - `func (n *Node) Active(now time.Time) bool` (models);
  - `func peerTransition(before, after *models.Node, now time.Time) (add, remove bool)` (rest).

- [ ] **Step 1: Write the failing tests**

`server/internal/shared/models/node_test.go`:

```go
package models

import (
	"net"
	"testing"
	"time"
)

func TestNodeActive(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	ip := net.ParseIP("10.0.0.5")
	cases := []struct {
		name string
		n    Node
		want bool
	}{
		{"active", Node{PublicKey: "k", VirtualIP: ip, Status: NodeStatusOnline}, true},
		{"future expiry", Node{PublicKey: "k", VirtualIP: ip, ExpiresAt: &future}, true},
		{"expired by time", Node{PublicKey: "k", VirtualIP: ip, ExpiresAt: &past}, false},
		{"expired status", Node{PublicKey: "k", VirtualIP: ip, Status: NodeStatusExpired}, false},
		{"no key", Node{VirtualIP: ip}, false},
		{"no ip", Node{PublicKey: "k"}, false},
		{"exactly at expiry", Node{PublicKey: "k", VirtualIP: ip, ExpiresAt: &now}, true}, // expired only once now is after expires_at, as enrichNode
	}
	for _, c := range cases {
		if got := c.n.Active(now); got != c.want {
			t.Errorf("%s: Active = %v, want %v", c.name, got, c.want)
		}
	}
}
```

`server/internal/controlplane/api/rest/node_transition_test.go`:

```go
package rest

import (
	"net"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// B11: the peer follows the node's activity, whatever the stored status said.
func TestPeerTransition(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	node := func(status models.NodeStatus, exp *time.Time) *models.Node {
		return &models.Node{PublicKey: "k", VirtualIP: net.ParseIP("10.0.0.5"), Status: status, ExpiresAt: exp}
	}
	cases := []struct {
		name          string
		before, after *models.Node
		add, remove   bool
	}{
		// The panel showed it expired (lazy), the DB still says online: extending must re-add.
		{"lazily expired, extended", node(models.NodeStatusOnline, &past), node(models.NodeStatusOnline, &future), true, false},
		{"stored expired, extended", node(models.NodeStatusExpired, &past), node(models.NodeStatusPending, &future), true, false},
		// Re-activating by status while expires_at is still in the past must NOT add the peer.
		{"status reactivated, still past", node(models.NodeStatusExpired, &past), node(models.NodeStatusOnline, &past), false, false},
		{"expired by status", node(models.NodeStatusOnline, nil), node(models.NodeStatusExpired, nil), false, true},
		{"expiry moved into the past", node(models.NodeStatusOnline, &future), node(models.NodeStatusOnline, &past), false, true},
		{"rename only", node(models.NodeStatusOnline, nil), node(models.NodeStatusOnline, nil), false, false},
	}
	for _, c := range cases {
		add, remove := peerTransition(c.before, c.after, now)
		if add != c.add || remove != c.remove {
			t.Errorf("%s: add=%v remove=%v, want add=%v remove=%v", c.name, add, remove, c.add, c.remove)
		}
	}
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failures `c.n.Active undefined` (models) and `undefined: peerTransition` (rest).

- [ ] **Step 3: Implement**

`models.go`, after the `Node` struct (add `"time"` to the imports if it is missing; it is used by `CreatedAt`):

```go
// Active reports whether the node may hold a WireGuard peer at time now: it
// has a key and an address, is not marked expired, and now is not after
// its expires_at.
func (n *Node) Active(now time.Time) bool {
	if n.PublicKey == "" || n.VirtualIP == nil || n.Status == NodeStatusExpired {
		return false
	}
	return n.ExpiresAt == nil || n.ExpiresAt.IsZero() || !now.After(*n.ExpiresAt)
}
```

`peer_restore.go`: delete `isNodeActive` and its comment. In `restorePeers`, replace `if !isNodeActive(node, now) {` with `if !node.Active(now) {`. Run `grep -rn "isNodeActive" server/internal` and update every other caller the same way.

`node_transition.go`:

```go
package rest

import (
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// peerTransition decides what an edit does to the node's WireGuard peer: add
// it when the node becomes active, remove it when it stops being active.
// "Active" is computed from status and expires_at, not from the stored
// status alone: lazy expiry never stored "expired" (B11).
func peerTransition(before, after *models.Node, now time.Time) (add, remove bool) {
	was, is := before.Active(now), after.Active(now)
	return !was && is, was && !is
}
```

`handlers.go` `handleUpdateNode`:
- Directly after the `node, err := s.store.GetNode(...)` not-found check, add `before := *node` (a copy).
- Replace the whole `// Update status if provided` block, including its `} else { … }` branch, up to (not including) `// Update NodeInfo if provided`, with:

```go
	// Update status if provided
	if req.Status != nil {
		node.Status = models.NodeStatus(*req.Status)
	} else if node.Status == models.NodeStatusExpired && req.ExpiresAt != nil && *req.ExpiresAt != "" {
		// A new expiry for an expired node re-activates it.
		node.Status = models.NodeStatusPending
	}
```

- Directly after the successful `s.store.UpdateNode` call (before `// Enrich with real-time data`), add:

```go
	// B11: the peer follows the node's activity.
	if add, remove := peerTransition(&before, node, time.Now()); add || remove {
		if mgr := s.getManager(node.NetworkID); mgr != nil {
			if add {
				slog.Info(fmt.Sprintf("Reactivating node %s, adding to WireGuard", node.Name))
				if err := mgr.AddPeer(node.PublicKey, node.VirtualIP.String()+"/32"); err != nil {
					slog.Error(fmt.Sprintf("Warning: failed to add reactivated peer to WireGuard: %v", err))
				}
			} else if err := mgr.RemovePeer(node.PublicKey); err != nil {
				slog.Error(fmt.Sprintf("Warning: failed to remove peer from WireGuard: %v", err))
			}
		}
	}
```

`firewall_handlers.go` `syncPeerAllowedIPs`: as the first statement inside `for _, node := range nodes {`, add:

```go
			if !node.Active(time.Now()) {
				continue // B11: never re-create an expired node's peer
			}
```

Add `"time"` to that file's imports if it is missing.

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`. `TestContract` is unchanged: `node_update` still returns the same body. `peer_restore_test.go` still passes.

- [ ] **Step 5: Commit**

```bash
git add server/internal/shared/models server/internal/controlplane/api/rest/peer_restore.go server/internal/controlplane/api/rest/node_transition.go server/internal/controlplane/api/rest/node_transition_test.go server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/firewall_handlers.go
git commit -m "fix: restore and remove peers by node activity (B11)"
```

---

### Task 2: Persist expiry in the store

**Files:**
- Modify: `server/internal/controlplane/store/store.go`
- Create: `server/internal/controlplane/store/expire_test.go`

**Interfaces:**
- Produces: `func (s *Store) ExpireNodes(ctx context.Context, now time.Time) ([]*models.Node, error)`. It marks nodes whose `expires_at` is before `now` as `expired` and returns exactly the nodes it changed, with ID, NetworkID, Name, PublicKey and VirtualIP set.

- [ ] **Step 1: Write the failing test** (`expire_test.go`)

```go
package store

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestExpireNodesPersistsOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.db.ExecContext(ctx, "DELETE FROM networks WHERE name = 'expire-net'")
	n := &models.Network{Name: "expire-net", CIDR: "10.81.0.0/24", ListenPort: 51981, InterfaceName: "wg181"}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), n.ID) })
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	mk := func(name, ip string, exp *time.Time) *models.Node {
		node := &models.Node{NetworkID: n.ID, Name: name, VirtualIP: net.ParseIP(ip),
			PublicKey: strings.Repeat(name[:1], 43) + "=", Labels: map[string]string{}, Status: models.NodeStatusOnline, ExpiresAt: exp}
		if err := s.CreateNode(ctx, node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	old := mk("a-old", "10.81.0.3", &past)
	mk("b-new", "10.81.0.4", &future)
	mk("c-none", "10.81.0.5", nil)

	got, err := s.ExpireNodes(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != old.ID || got[0].NetworkID != n.ID || got[0].PublicKey != old.PublicKey || got[0].VirtualIP.String() != "10.81.0.3" {
		t.Fatalf("ExpireNodes = %+v, want only a-old with its key and IP", got)
	}
	stored, _ := s.GetNode(ctx, old.ID)
	if stored.Status != models.NodeStatusExpired {
		t.Fatalf("status = %s, want expired", stored.Status)
	}
	if again, err := s.ExpireNodes(ctx, now); err != nil || len(again) != 0 {
		t.Fatalf("second run = %v, %v; an expired node is reported once", again, err)
	}
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure in `store`, `s.ExpireNodes undefined`.

- [ ] **Step 3: Implement** (`store.go`)

```go
// ExpireNodes marks every node whose expires_at is before now as expired and
// returns the nodes it changed (ID, NetworkID, Name, PublicKey, VirtualIP).
// A node is reported only once: the next call skips it.
func (s *Store) ExpireNodes(ctx context.Context, now time.Time) ([]*models.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		UPDATE nodes SET status = 'expired'
		WHERE expires_at IS NOT NULL AND expires_at < $1 AND status IS DISTINCT FROM 'expired'
		RETURNING id, network_id, name, public_key, host(virtual_ip)`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.Node{}
	for rows.Next() {
		n := &models.Node{Status: models.NodeStatusExpired}
		var ip string
		if err := rows.Scan(&n.ID, &n.NetworkID, &n.Name, &n.PublicKey, &ip); err != nil {
			return nil, err
		}
		n.VirtualIP = net.ParseIP(ip)
		out = append(out, n)
	}
	return out, rows.Err()
}
```

(`host(inet)` returns the address without the prefix length.)

- [ ] **Step 4: Run it and verify it passes**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/store/store.go server/internal/controlplane/store/expire_test.go
git commit -m "feat: persist node expiry in the store"
```

---

### Task 3: The reconciler (plan, expire step, shadow and enforce)

**Files:**
- Create: `server/internal/controlplane/reconciler/plan.go`, `server/internal/controlplane/reconciler/reconciler.go`, `server/internal/controlplane/reconciler/reconciler_test.go`

**Interfaces:**
- Consumes: `(*models.Node).Active`, `(*store.Store).ExpireNodes`, `wireguard.PeerStatus`.
- Produces:

```go
type Mode string // ModeOff "off", ModeShadow "shadow", ModeEnforce "enforce"
func ParseMode(s string) (Mode, error) // "" -> shadow
type PeerControl interface {
	GetPeers() (map[string]wireguard.PeerStatus, error)
	AddPeer(publicKey, allowedIPs string) error
	UpdatePeerAllowedIPs(publicKey, allowedIPs string) error
	RemovePeer(publicKey string) error
}
type Store interface {
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	ListNodes(ctx context.Context, networkID string) ([]*models.Node, error)
	GetNode(ctx context.Context, id string) (*models.Node, error)
	ExpireNodes(ctx context.Context, now time.Time) ([]*models.Node, error)
}
type Action struct{ Interface, Kind, NodeID, Node, PublicKey, AllowedIPs string } // Kind: "add" | "update" | "remove"
type Report struct {
	Time    time.Time
	Mode    Mode
	Expired []string // node names
	Actions []Action // planned (shadow) or applied (enforce)
	Unknown []string // "wg1:<public key>"
	Errors  []string
}
func (r Report) OK() bool
type Reconciler struct{ Mode Mode; Store Store; Peers func(iface string) PeerControl; Now func() time.Time /* + unexported */ }
func New(mode Mode, st Store, peers func(string) PeerControl) *Reconciler
func (r *Reconciler) RunOnce(ctx context.Context) Report
```

- [ ] **Step 1: Write the failing tests** (`reconciler_test.go`)

```go
package reconciler

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func key(c string) string { return strings.Repeat(c, 43) + "=" }

// fakeWG is one interface's peers; calls records every change.
type fakeWG struct {
	mu    sync.Mutex
	peers map[string]wireguard.PeerStatus
	calls []string
	err   error
}

func (f *fakeWG) GetPeers() (map[string]wireguard.PeerStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]wireguard.PeerStatus{}
	for k, v := range f.peers {
		out[k] = v
	}
	return out, nil
}
func (f *fakeWG) set(op, k, ips string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+" "+k[:1]+" "+ips)
	if op == "remove" {
		delete(f.peers, k)
	} else {
		f.peers[k] = wireguard.PeerStatus{PublicKey: k, AllowedIPs: ips}
	}
	return nil
}
func (f *fakeWG) AddPeer(k, ips string) error              { return f.set("add", k, ips) }
func (f *fakeWG) UpdatePeerAllowedIPs(k, ips string) error { return f.set("update", k, ips) }
func (f *fakeWG) RemovePeer(k string) error                { return f.set("remove", k, "") }

type fakeStore struct {
	networks []*models.Network
	nodes    map[string]*models.Node // by ID
	expired  []*models.Node
}

func (s *fakeStore) ListNetworks(context.Context) ([]*models.Network, error) { return s.networks, nil }
func (s *fakeStore) ListNodes(_ context.Context, netID string) ([]*models.Node, error) {
	out := []*models.Node{}
	for _, n := range s.nodes {
		if n.NetworkID == netID {
			c := *n
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (s *fakeStore) GetNode(_ context.Context, id string) (*models.Node, error) {
	if n, ok := s.nodes[id]; ok {
		c := *n
		return &c, nil
	}
	return nil, nil
}
func (s *fakeStore) ExpireNodes(_ context.Context, at time.Time) ([]*models.Node, error) {
	out := []*models.Node{}
	for _, n := range s.nodes {
		if n.ExpiresAt != nil && n.ExpiresAt.Before(at) && n.Status != models.NodeStatusExpired {
			n.Status = models.NodeStatusExpired
			c := *n
			out = append(out, &c)
		}
	}
	return out, nil
}

func node(id, netID, k, ip string, status models.NodeStatus, exp *time.Time) *models.Node {
	return &models.Node{ID: id, NetworkID: netID, Name: "node-" + id, PublicKey: key(k), VirtualIP: net.ParseIP(ip), Status: status, ExpiresAt: exp}
}

// setup: wg1 has a (active, live), b (active, missing), c (expired by time, live),
// d (live with /32 missing from allowed-ips), and an unknown live peer u.
func setup(mode Mode) (*Reconciler, *fakeStore, *fakeWG) {
	past := now.Add(-time.Hour)
	st := &fakeStore{
		networks: []*models.Network{{ID: "n1", Name: "Office", CIDR: "10.20.0.0/24", InterfaceName: "wg1"}},
		nodes: map[string]*models.Node{
			"a": node("a", "n1", "a", "10.20.0.3", models.NodeStatusOnline, nil),
			"b": node("b", "n1", "b", "10.20.0.4", models.NodeStatusOnline, nil),
			"c": node("c", "n1", "c", "10.20.0.5", models.NodeStatusOnline, &past),
			"d": node("d", "n1", "d", "10.20.0.6", models.NodeStatusOnline, nil),
		},
	}
	wg := &fakeWG{peers: map[string]wireguard.PeerStatus{
		key("a"): {AllowedIPs: "10.20.0.3/32"},
		key("c"): {AllowedIPs: "10.20.0.5/32"},
		key("d"): {AllowedIPs: "192.168.50.0/24"}, // a site gateway's LAN route
		key("u"): {AllowedIPs: "10.20.0.99/32"},
	}}
	r := New(mode, st, func(iface string) PeerControl { return wg })
	r.Now = func() time.Time { return now }
	return r, st, wg
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeShadow, "SHADOW": ModeShadow, " enforce ": ModeEnforce, "off": ModeOff} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("on"); err == nil {
		t.Error("unknown modes must be rejected")
	}
}

func TestShadowExpiresButOnlyLogsTheDiff(t *testing.T) {
	r, st, wg := setup(ModeShadow)
	rep := r.RunOnce(context.Background())
	// The expire step runs in shadow too: c is marked expired and its peer removed.
	if st.nodes["c"].Status != models.NodeStatusExpired || strings.Join(rep.Expired, ",") != "node-c" {
		t.Fatalf("expire step: status=%s report=%v", st.nodes["c"].Status, rep.Expired)
	}
	if strings.Join(wg.calls, ";") != "remove c " {
		t.Fatalf("shadow may only remove the expired peer, calls=%v", wg.calls)
	}
	kinds := []string{}
	for _, a := range rep.Actions {
		kinds = append(kinds, a.Kind+":"+a.Node)
	}
	sort.Strings(kinds)
	if strings.Join(kinds, ",") != "add:node-b,update:node-d" {
		t.Fatalf("planned actions = %v", kinds)
	}
	if len(rep.Unknown) != 1 || rep.Unknown[0] != "wg1:"+key("u") || !rep.OK() {
		t.Fatalf("unknown=%v errors=%v", rep.Unknown, rep.Errors)
	}
}

func TestEnforceAppliesTheDiff(t *testing.T) {
	r, _, wg := setup(ModeEnforce)
	r.RunOnce(context.Background())
	got := map[string]string{}
	for k, p := range wg.peers {
		got[k[:1]] = p.AllowedIPs
	}
	if got["b"] != "10.20.0.4/32" {
		t.Errorf("missing peer b must be added, peers=%v", got)
	}
	if _, ok := got["c"]; ok {
		t.Errorf("expired peer c must be gone, peers=%v", got)
	}
	if _, ok := got["u"]; !ok {
		t.Errorf("unknown peer u must never be removed, peers=%v", got)
	}
}

func TestEnforceNeverShrinksAllowedIPs(t *testing.T) {
	r, _, wg := setup(ModeEnforce)
	r.RunOnce(context.Background())
	if ips := wg.peers[key("d")].AllowedIPs; ips != "192.168.50.0/24,10.20.0.6/32" {
		t.Fatalf("d allowed-ips = %q, want the gateway route kept and the /32 added", ips)
	}
}

func TestEnforceRechecksBeforeApplying(t *testing.T) {
	r, st, wg := setup(ModeEnforce)
	// b is deleted after the plan is made (between ListNodes and the apply).
	r.beforeApply = func() { delete(st.nodes, "b") }
	rep := r.RunOnce(context.Background())
	if _, ok := wg.peers[key("b")]; ok {
		t.Fatal("a node deleted before the apply must not get its peer back")
	}
	for _, a := range rep.Actions {
		if a.Node == "node-b" {
			t.Fatalf("a skipped action must not be reported as applied: %+v", rep.Actions)
		}
	}
}

func TestOneBrokenInterfaceDoesNotStopTheOthers(t *testing.T) {
	st := &fakeStore{
		networks: []*models.Network{
			{ID: "n1", CIDR: "10.20.0.0/24", InterfaceName: "wg1"},
			{ID: "n2", CIDR: "10.30.0.0/24", InterfaceName: "wg2"},
		},
		nodes: map[string]*models.Node{"x": node("x", "n2", "x", "10.30.0.3", models.NodeStatusOnline, nil)},
	}
	broken := &fakeWG{err: errors.New("Unable to access interface: No such device")}
	good := &fakeWG{peers: map[string]wireguard.PeerStatus{}}
	r := New(ModeEnforce, st, func(iface string) PeerControl {
		if iface == "wg1" {
			return broken
		}
		return good
	})
	r.Now = func() time.Time { return now }
	rep := r.RunOnce(context.Background())
	if rep.OK() || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "wg1") {
		t.Fatalf("errors = %v, want one for wg1", rep.Errors)
	}
	if _, ok := good.peers[key("x")]; !ok {
		t.Fatal("wg2 must still be reconciled")
	}
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure in `internal/controlplane/reconciler`: `undefined: New`, `undefined: ParseMode`.

- [ ] **Step 3: Implement**

`plan.go`:

```go
package reconciler

import (
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// plan compares one network's nodes with its live peers. Active nodes must
// be peers with their /32 among the allowed-ips; peers of inactive nodes go;
// peers that belong to no node are reported, never removed (adopt).
func plan(nw *models.Network, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) ([]Action, []string) {
	var actions []Action
	known := map[string]bool{}
	for _, n := range nodes {
		known[n.PublicKey] = true
		peer, isLive := live[n.PublicKey]
		if !n.Active(now) {
			if isLive {
				actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "remove", NodeID: n.ID, Node: n.Name, PublicKey: n.PublicKey})
			}
			continue
		}
		own := n.VirtualIP.String() + "/32"
		if !isLive {
			actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "add", NodeID: n.ID, Node: n.Name, PublicKey: n.PublicKey, AllowedIPs: own})
			continue
		}
		ips := allowedList(peer.AllowedIPs)
		if !contains(ips, own) {
			actions = append(actions, Action{Interface: nw.InterfaceName, Kind: "update", NodeID: n.ID, Node: n.Name, PublicKey: n.PublicKey,
				AllowedIPs: strings.Join(append(ips, own), ",")}) // never shrink: keep gateway routes
		}
	}
	var unknown []string
	for k := range live {
		if !known[k] {
			unknown = append(unknown, nw.InterfaceName+":"+k)
		}
	}
	return actions, unknown
}

// allowedList splits `wg show dump` allowed-ips ("(none)" means empty).
func allowedList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && p != "(none)" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
```

`reconciler.go`:

```go
// Package reconciler keeps WireGuard peers equal to the database: active
// nodes are peers, inactive ones are not. In shadow mode it only reports the
// difference; in enforce mode it applies it. Expired nodes are marked and
// their peers removed in both modes (the lazy expiry of the panel, on time).
package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// Mode selects what the reconciler may change (WG_RECONCILER).
type Mode string

const (
	ModeOff     Mode = "off"
	ModeShadow  Mode = "shadow"
	ModeEnforce Mode = "enforce"
)

// ParseMode reads WG_RECONCILER; empty means shadow.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return ModeShadow, nil
	case ModeOff, ModeShadow, ModeEnforce:
		return m, nil
	}
	return "", fmt.Errorf("unknown WG_RECONCILER %q (use off, shadow or enforce)", s)
}

// PeerControl is what the reconciler needs from one WireGuard interface;
// *wireguard.Manager satisfies it.
type PeerControl interface {
	GetPeers() (map[string]wireguard.PeerStatus, error)
	AddPeer(publicKey, allowedIPs string) error
	UpdatePeerAllowedIPs(publicKey, allowedIPs string) error
	RemovePeer(publicKey string) error
}

// Store is what the reconciler reads and writes; *store.Store satisfies it.
type Store interface {
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	ListNodes(ctx context.Context, networkID string) ([]*models.Node, error)
	GetNode(ctx context.Context, id string) (*models.Node, error)
	ExpireNodes(ctx context.Context, now time.Time) ([]*models.Node, error)
}

// Action is one peer change, planned (shadow) or applied (enforce).
type Action struct {
	Interface, Kind, NodeID, Node, PublicKey, AllowedIPs string
}

// Report describes one run.
type Report struct {
	Time    time.Time
	Mode    Mode
	Expired []string
	Actions []Action
	Unknown []string
	Errors  []string
}

// OK reports whether the run had no errors.
func (r Report) OK() bool { return len(r.Errors) == 0 }

// Reconciler compares the database with the kernel's WireGuard peers.
type Reconciler struct {
	Mode  Mode
	Store Store
	Peers func(iface string) PeerControl
	Now   func() time.Time

	beforeApply func() // test hook: runs between planning and applying

	mu      sync.Mutex
	last    Report
	trigger chan struct{}
}

// New returns a reconciler; Run starts its loop.
func New(mode Mode, st Store, peers func(string) PeerControl) *Reconciler {
	return &Reconciler{Mode: mode, Store: st, Peers: peers, Now: time.Now, trigger: make(chan struct{}, 1)}
}

// RunOnce runs the expire step, then plans (shadow) or applies (enforce) the
// difference for every network with an interface.
func (r *Reconciler) RunOnce(ctx context.Context) Report {
	now := r.Now()
	rep := Report{Time: now, Mode: r.Mode}
	networks, err := r.Store.ListNetworks(ctx)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("list networks: %v", err))
		r.finish(rep)
		return rep
	}
	ifaces := map[string]string{} // network ID -> interface
	for _, nw := range networks {
		if nw.InterfaceName != "" {
			ifaces[nw.ID] = nw.InterfaceName
		}
	}

	// Expire step (shadow and enforce): mark and remove expired nodes' peers.
	expired, err := r.Store.ExpireNodes(ctx, now)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("expire nodes: %v", err))
	}
	for _, n := range expired {
		rep.Expired = append(rep.Expired, n.Name)
		iface, ok := ifaces[n.NetworkID]
		if !ok {
			continue
		}
		pc := r.Peers(iface)
		live, err := pc.GetPeers()
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: read peers: %v", iface, err))
			continue
		}
		if _, ok := live[n.PublicKey]; ok {
			if err := pc.RemovePeer(n.PublicKey); err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: remove expired %s: %v", iface, n.Name, err))
			}
		}
		slog.Info("reconciler: node expired", "node", n.Name, "interface", iface)
	}

	// Diff step.
	type planned struct {
		pc      PeerControl
		actions []Action
	}
	var plans []planned
	for _, nw := range networks {
		if nw.InterfaceName == "" {
			continue
		}
		pc := r.Peers(nw.InterfaceName)
		live, err := pc.GetPeers()
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: read peers: %v", nw.InterfaceName, err))
			continue
		}
		nodes, err := r.Store.ListNodes(ctx, nw.ID)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: list nodes: %v", nw.InterfaceName, err))
			continue
		}
		actions, unknown := plan(nw, nodes, live, now)
		sort.Strings(unknown)
		rep.Unknown = append(rep.Unknown, unknown...)
		plans = append(plans, planned{pc, actions})
	}

	if r.beforeApply != nil {
		r.beforeApply()
	}
	for _, p := range plans {
		for _, a := range p.actions {
			if r.Mode != ModeEnforce {
				slog.Info("reconciler (shadow): would change peer", "kind", a.Kind, "node", a.Node, "interface", a.Interface, "allowed_ips", a.AllowedIPs)
				rep.Actions = append(rep.Actions, a)
				continue
			}
			if !r.stillValid(ctx, a, now) {
				continue
			}
			var err error
			switch a.Kind {
			case "add":
				err = p.pc.AddPeer(a.PublicKey, a.AllowedIPs)
			case "update":
				err = p.pc.UpdatePeerAllowedIPs(a.PublicKey, a.AllowedIPs)
			case "remove":
				err = p.pc.RemovePeer(a.PublicKey)
			}
			if err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %s %s: %v", a.Interface, a.Kind, a.Node, err))
				continue
			}
			slog.Info("reconciler: changed peer", "kind", a.Kind, "node", a.Node, "interface", a.Interface, "allowed_ips", a.AllowedIPs)
			rep.Actions = append(rep.Actions, a)
		}
	}
	for _, u := range rep.Unknown {
		slog.Warn("reconciler: peer not in the database (left alone)", "peer", u)
	}
	for _, e := range rep.Errors {
		slog.Error("reconciler error: " + e)
	}
	r.finish(rep)
	return rep
}

// stillValid re-reads the node right before an enforce change, so a node
// deleted or changed after planning never gets its peer back.
func (r *Reconciler) stillValid(ctx context.Context, a Action, now time.Time) bool {
	n, err := r.Store.GetNode(ctx, a.NodeID)
	if err != nil {
		return false
	}
	if a.Kind == "remove" {
		return n == nil || !n.Active(now)
	}
	return n != nil && n.PublicKey == a.PublicKey && n.Active(now)
}

func (r *Reconciler) finish(rep Report) {
	r.mu.Lock()
	r.last = rep
	r.mu.Unlock()
}
```

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: `ok …/internal/controlplane/reconciler` and all other packages `ok`. Also check that `TestLogLevelsMatchMessages` still passes. Its directory list does not include `reconciler` yet; Task 6 widens it. The new messages carry no alarm words at Info except `reconciler error:` (Error) and the unknown peer line (Warn).

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/reconciler
git commit -m "feat: add WireGuard reconciler with shadow and enforce modes"
```

---

### Task 4: Run loop, triggers, health and wiring

**Files:**
- Modify: `server/internal/controlplane/reconciler/reconciler.go` (`Run`, `Trigger`, `Status`), `reconciler_test.go`
- Create: `server/internal/controlplane/api/rest/reconciler_wiring.go`
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`Server` struct field, `handleHealth`, triggers)
- Modify: `server/internal/controlplane/api/rest/config_handlers.go` (trigger after node create)
- Modify: `server/internal/controlplane/api/rest/health_test.go`
- Modify: `server/cmd/control-plane/main.go`, `server/deployments/docker/docker-compose.yml`

**Interfaces:**
- Produces:
  - `(*Reconciler).Run(ctx context.Context, every time.Duration)`;
  - `(*Reconciler).Trigger()`;
  - `(*Reconciler).Status() Report`;
  - `(*rest.Server).SetReconciler(r *reconciler.Reconciler)`;
  - `(*Server).triggerReconcile()`.

- [ ] **Step 1: Write the failing tests**

Append to `reconciler_test.go`:

```go
func TestRunLoopTriggersCoalesceAndStop(t *testing.T) {
	r, _, _ := setup(ModeShadow)
	var mu sync.Mutex
	runs := 0
	r.beforeApply = func() { mu.Lock(); runs++; mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	for i := 0; i < 50; i++ {
		r.Trigger() // must never block, however many arrive
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := runs
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must return after the context is cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	if runs < 1 || runs > 2 {
		t.Fatalf("50 triggers must coalesce into 1-2 runs, got %d", runs)
	}
	if st := r.Status(); st.Time.IsZero() || st.Mode != ModeShadow {
		t.Fatalf("Status after a run = %+v", st)
	}
}
```

Append to `health_test.go`:

```go
func TestHealthReportsReconciler(t *testing.T) {
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	rec := reconciler.New(reconciler.ModeShadow, st, func(string) reconciler.PeerControl { return brokenPeers{} })
	s.SetReconciler(rec)
	rec.RunOnce(context.Background())
	var body struct {
		Status string `json:"status"`
		Checks struct {
			Reconciler struct {
				OK      bool   `json:"ok"`
				Mode    string `json:"mode"`
				LastRun string `json:"last_run"`
				Pending int    `json:"pending"`
			} `json:"reconciler"`
		} `json:"checks"`
	}
	r := callAs(t, s, "GET", "/health", "", false)
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Checks.Reconciler.Mode != "shadow" || body.Checks.Reconciler.OK || body.Checks.Reconciler.LastRun == "" || body.Status != "degraded" {
		t.Fatalf("a reconciler that cannot read interfaces is degraded: %+v", body)
	}
}

// brokenPeers fails like an interface that is down.
type brokenPeers struct{}

func (brokenPeers) GetPeers() (map[string]wireguard.PeerStatus, error) {
	return nil, fmt.Errorf("Unable to access interface")
}
func (brokenPeers) AddPeer(string, string) error              { return nil }
func (brokenPeers) UpdatePeerAllowedIPs(string, string) error { return nil }
func (brokenPeers) RemovePeer(string) error                   { return nil }
```

(Add the imports `context`, `fmt`, `github.com/novusgate/novusgate/internal/controlplane/reconciler` and `github.com/novusgate/novusgate/internal/wireguard` to `health_test.go`.)

- [ ] **Step 2: Run them and verify they fail**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failures, `r.Run undefined` / `s.SetReconciler undefined`.

- [ ] **Step 3: Implement**

Append to `reconciler.go`:

```go
// Run reconciles every interval and whenever Trigger is called, until ctx
// is cancelled. The first run happens after one interval (or a trigger), so
// startup (loadNetworks bringing interfaces up and adopting peers) goes first.
func (r *Reconciler) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.trigger:
		}
		r.RunOnce(ctx)
	}
}

// Trigger asks for a run soon; it never blocks and repeated calls coalesce.
func (r *Reconciler) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Status returns the last run's report.
func (r *Reconciler) Status() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}
```

`rest/reconciler_wiring.go`:

```go
package rest

import "github.com/novusgate/novusgate/internal/controlplane/reconciler"

// SetReconciler attaches the WireGuard reconciler (nil when WG_RECONCILER=off).
func (s *Server) SetReconciler(r *reconciler.Reconciler) { s.reconciler = r }

// triggerReconcile asks the reconciler for a run after a write that changes
// peers; without a reconciler it does nothing.
func (s *Server) triggerReconcile() {
	if s.reconciler != nil {
		s.reconciler.Trigger()
	}
}
```

`handlers.go`:
- Add the field `reconciler *reconciler.Reconciler` to the `Server` struct, next to `firewall`, and add the import.
- In `handleHealth`, before `checks["firewall"] = fw`, add:

```go
	if s.reconciler != nil {
		rep := s.reconciler.Status()
		rc := map[string]interface{}{"ok": rep.OK(), "mode": string(s.reconciler.Mode), "pending": 0, "last_run": nil}
		if !rep.Time.IsZero() {
			rc["last_run"] = rep.Time.UTC().Format(time.RFC3339)
			if rep.Mode != reconciler.ModeEnforce {
				rc["pending"] = len(rep.Actions) // shadow: changes enforce would make
			}
		}
		healthy = healthy && rep.OK()
		checks["reconciler"] = rc
	}
```

- Add `s.triggerReconcile()` as the last statement before the success response in these handlers:
  - `handleUpdateNode` (before `jsonResponse(w, http.StatusOK, node)`);
  - `handleDeleteNode` (before its success `jsonResponse`);
  - `handleCreateNetwork` (before its 201 `jsonResponse`);
  - `handleDeleteNetwork` (before `w.WriteHeader(http.StatusNoContent)`);
  - `handleSyncPeers` (before its success `jsonResponse`);
  - `config_handlers.go` `handleCreateServerWithConfig` (before its 201 `jsonResponse`).

`main.go` `runServer`, directly after `apiServer := rest.NewServer(db)`:

```go
	// WireGuard reconciler: off | shadow (default: report only) | enforce.
	wgMode, err := reconciler.ParseMode(os.Getenv("WG_RECONCILER"))
	if err != nil {
		return err
	}
	recCtx, stopReconciler := context.WithCancel(context.Background())
	defer stopReconciler()
	if wgMode != reconciler.ModeOff {
		rec := reconciler.New(wgMode, db, func(iface string) reconciler.PeerControl { return wireguard.NewManager(iface) })
		apiServer.SetReconciler(rec)
		go rec.Run(recCtx, 15*time.Second)
		slog.Info(fmt.Sprintf("  WireGuard reconciler: %s", wgMode))
	}
```

Add the import `github.com/novusgate/novusgate/internal/controlplane/reconciler`. Add `stopReconciler()` right after `<-quit`, so the loop stops before the HTTP server shuts down. The `defer` stays as a safety net.

`docker-compose.yml`, below `LOG_LEVEL`:

```yaml
      WG_RECONCILER: ${WG_RECONCILER:-shadow}
```

- [ ] **Step 4: Run them and verify they pass**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`. `TestContract` is unchanged: the contract server has no reconciler, so there is no `checks.reconciler`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/reconciler server/internal/controlplane/api/rest server/cmd/control-plane/main.go server/deployments/docker/docker-compose.yml
git commit -m "feat: run the reconciler loop and report it in /health"
```

---

### Task 5: Create a network without a second `Up`

`CreateServerConfigWithKey` → `SetupInterface` already ends with `m.Up()`. `handleCreateNetwork` then calls `mgr.Up()` again, which always fails ("already exists") and logs an Error for every new network.

**Files:**
- Modify: `server/internal/controlplane/api/rest/handlers.go` (`handleCreateNetwork`; add the `wgCreateInterface` seam next to `wgInit`)
- Modify: `server/internal/controlplane/api/rest/contract_test.go` (restore the new seam in `newContractServer`)
- Create: `server/internal/controlplane/api/rest/network_create_test.go`

**Interfaces:**
- Produces: `var wgCreateInterface func(m *wireguard.Manager, privateKey, address string, port int) error`.

- [ ] **Step 1: Write the failing test** (`network_create_test.go`)

```go
package rest

import (
	"strings"
	"testing"

	"github.com/novusgate/novusgate/internal/wireguard"
)

// SetupInterface already brings the interface up; a second Up always fails
// with "already exists" and logged a false error for every new network.
func TestCreateNetworkBringsTheInterfaceUpOnce(t *testing.T) {
	logs := captureLogs(t)
	s, st, _ := newContractServer(t)
	seedContract(t, st)
	created := []string{}
	wgInit = func(*wireguard.Manager) error { return nil } // pretend wg is installed
	wgCreateInterface = func(m *wireguard.Manager, _, addr string, _ int) error {
		created = append(created, m.InterfaceName+" "+addr)
		return nil
	}
	if rec := callAs(t, s, "POST", "/api/v1/networks", `{"name":"contract-up","cidr":"10.76.0.0/24"}`, true); rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if len(created) != 1 || !strings.HasSuffix(created[0], " 10.76.0.1/24") {
		t.Fatalf("interface setup calls = %v", created)
	}
	if strings.Contains(logs.String(), "Failed to bring up") {
		t.Fatalf("no second Up may run:\n%s", logs.String())
	}
}
```

In `newContractServer`, save and restore `wgCreateInterface` the same way as `wgInit`. It needs no default stub: `wgInit` already fails in tests, so `wgCreateInterface` is never reached unless a test overrides `wgInit`.

- [ ] **Step 2: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure, `undefined: wgCreateInterface`.

- [ ] **Step 3: Implement**

Next to `wgInit` in `handlers.go`:

```go
// wgCreateInterface writes the network's wg-quick config and brings the
// interface up (SetupInterface ends with Up); replaced in tests.
var wgCreateInterface = func(m *wireguard.Manager, privateKey, address string, port int) error {
	return m.CreateServerConfigWithKey(privateKey, address, port)
}
```

In `handleCreateNetwork`, replace `} else if err := mgr.CreateServerConfigWithKey(privateKey, serverAddr, port); err != nil {` with `} else if err := wgCreateInterface(mgr, privateKey, serverAddr, port); err != nil {`.

In the `else` branch that follows, delete:

```go
			// Bring up the interface
			if err := mgr.Up(); err != nil {
				slog.Error(fmt.Sprintf("Warning: Failed to bring up %s: %v", network.InterfaceName, err))
			}
```

Keep the `WireGuard interface %s created …` info line.

- [ ] **Step 4: Run it and verify it passes**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/api/rest/handlers.go server/internal/controlplane/api/rest/contract_test.go server/internal/controlplane/api/rest/network_create_test.go
git commit -m "fix: bring a new network's interface up once"
```

---

### Task 6: The logging guard covers all of `internal/` and import aliases

This closes P2b deferred minor #5 before new packages, such as `reconciler`, can slip past.

**Files:**
- Modify: `server/internal/shared/logging/noprint_test.go`

- [ ] **Step 1: Write the failing test**

Replace `runtimeDirs` with a walk, and resolve import names per file:

```go
// runtimeFiles returns every non-test Go file under internal/ (server
// runtime code), plus cmd/control-plane/main.go, which is handled per function.
func runtimeFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// importNames maps a file's local package names for "fmt", "log" and
// "log/slog" (handling aliases like stdlog "log").
func importNames(file *ast.File) map[string]string {
	names := map[string]string{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path != "fmt" && path != "log" && path != "log/slog" {
			continue
		}
		local := filepath.Base(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		names[local] = path
	}
	return names
}
```

Change both checks so they resolve the selector's identifier through `importNames(file)`:
- forbidden: `fmt` `Print*`, `log` `Print*`/`Fatal*`/`Panic*`, and `fmt` `Fprint*` to `os.Stdout`/`os.Stderr`;
- level check: `slog` `Info`/`Debug`.

To do that, pass the file's map into `check`, and compare `names[pkg.Name] == "fmt"` and so on, instead of `pkg.Name == "fmt"`. Also flag a call to `log.Default()`. Iterate over `runtimeFiles(t)` instead of `runtimeDirs`. Keep the `main.go` per-function handling as it is.

Add a self-test that proves aliases are caught:

```go
func TestGuardCatchesAliasedImports(t *testing.T) {
	src := "package x\nimport stdlog \"log\"\nfunc f() { stdlog.Printf(\"x\") }\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bad := directPrints(fset, file, file); len(bad) != 1 {
		t.Fatalf("aliased log.Printf must be caught, got %v", bad)
	}
}
```

To make this testable, factor the forbidden-call inspection into `directPrints(fset *token.FileSet, file *ast.File, n ast.Node) []string` and the level inspection into `quietAlarms(fset *token.FileSet, file *ast.File, n ast.Node) []string`. Both tests call them. Add the imports `io/fs` and `go/token` if they are missing.

- [ ] **Step 2: Run it and verify it fails**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: build failure, `undefined: directPrints`. Once implemented, the walk must report nothing new; if it does, convert those calls under the P2b rules in this task.

- [ ] **Step 3: Implement** the refactor described in Step 1, so that `TestRuntimeCodeLogsThroughSlog`, `TestLogLevelsMatchMessages` and `TestGuardCatchesAliasedImports` all use `runtimeFiles`, `importNames`, `directPrints` and `quietAlarms`.

- [ ] **Step 4: Run it and verify it passes**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`. The walk includes `internal/controlplane/reconciler` and `internal/shared/models`.

- [ ] **Step 5: Commit**

```bash
git add server/internal/shared/logging/noprint_test.go
git commit -m "test: guard every internal package and aliased log imports"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/api.md` (`/health` → `checks.reconciler`; `PUT /nodes/{id}` peer behaviour)
- Modify: `docs/architecture.md` (reconciler section)
- Modify: `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md` (P2c decisions; P2c-2 deferral)
- Modify: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` (§7 B11 → closed with hashes)
- Create: `docs/runbooks/p2c-reconciler.md` (staging: shadow log, expiry, enforce switch, revert)
- Modify: `docs/active-context.md`

- [ ] **Step 1: Write**
  - **`docs/architecture.md`**, a "Reconciler (P2c)" section:
    - `WG_RECONCILER` (off / shadow default / enforce; an invalid value stops startup);
    - a 15 s tick, plus a trigger after node and network writes;
    - the expire step (both modes) and the diff step (shadow logs `reconciler (shadow): would change peer`, enforce applies with a DB re-check);
    - unknown peers are reported (`reconciler: peer not in the database (left alone)`) and never removed;
    - allowed-ips are never shrunk;
    - `wgN.conf` peers are deferred to P2c-2, with the reason.
  - **`docs/api.md`:**
    - `/health` `checks.reconciler {ok, mode, last_run, pending}` appears only when the reconciler runs; `pending` is the shadow difference.
    - `PUT /nodes/{id}`: the peer is added when the node becomes active (for example a new future `expires_at`), and removed when it stops being active. The response shape is unchanged.
  - **P2 spec:** add a "P2c qərarları" section listing the Global Constraints above (expire step in shadow, never shrink, adopt, P2c-2 for `wgN.conf`).
  - **Master spec §7 B11:** add "P2c-də bağlandı (`<hashes>`)".
  - **`docs/runbooks/p2c-reconciler.md`** (Azerbaijani; each step with command and expected output; results appended):
    1. Default `shadow`. After 15–30 s, `docker logs novusgate-control-plane | grep reconciler` shows either nothing or `would change peer` lines. Every such line is drift: write it down.
    2. `curl -s http://<vpn-ip>:8080/health | jq .checks.reconciler` → `mode: shadow`, `ok: true`.
    3. Expiry: set a test node's `expires_at` 1 minute ahead from the panel, close the panel, and wait 2 minutes.
       - `wg show wg0 peers` must no longer list it.
       - `GET /networks/{id}/nodes` must show `status: expired`.
    4. Re-activation: give it a future `expires_at` → `wg show` lists the peer again within seconds (B11).
    5. Only after step 1 shows no unexplained drift for a day: set `WG_RECONCILER=enforce` in `.env`, then `docker compose up -d control-plane`. Delete a test node's peer by hand (`wg set wg0 peer <key> remove`); within 15 s it is back. Add a foreign peer by hand: it stays, and the log shows `peer not in the database (left alone)`.
    6. Revert: `WG_RECONCILER=shadow` (or `off`), then `docker compose up -d control-plane`.
  - **`docs/active-context.md`:** a session block plus table rows.

- [ ] **Step 2: Verify**

Run: `bash server/scripts/test-with-postgres.sh`
Expected: all `ok`.

- [ ] **Step 3: Commit**

```bash
git add docs
git commit -m "docs: document the P2c reconciler, expiry and runbook"
```

---

## Out of scope
- **P2c-2:** `[Peer]` sections in `wgN.conf` from the DB (`wg syncconf` instead of `Down`/`Up`), and the end of `loadNetworks`' separate restore/import path once the reconciler owns it.
- **P2d:** the service layer, the unified error format, OpenAPI.
- **Status validation in `PUT /nodes/{id}`** (any string is accepted today): P2d DTO validation.
