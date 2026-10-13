# P1 — Stabilizasiya: İmplementasiya Planı

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Data itkisi, lockout, crash və reboot baqlarını (A1–A6, B17–B19) mövcud funksionallığı dəyişmədən bağlamaq və layihəyə ilk test/CI bünövrəsini qoymaq.

**Architecture:** Lokal, kiçik düzəlişlər edilir, arxitektura dəyişmir. Test oluna bilməyən hissələr əvvəl çıxarılır:
- Center skriptləri `lib/scripts.js` moduluna.
- SSE xətası `lib/sse.js` moduluna.
- Peer bərpası təmiz Go funksiyasına.
- `setup-firewall.sh` funksiyalara.

Sonra hər düzəliş öz testi ilə gəlir.

**Tech Stack:** Go 1.23 (`testing`), Node 20 (`node:test`, yeni paket yoxdur), bash 5 + Ubuntu 24.04 (shell testləri), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` (§3 sındırmamaq qaydaları, §7.A və §7.B).

## Global Constraints

- Yeni paket əlavə olunmur: Go-da yalnız standart kitabxana, Node-da `node:test`.
- API cavab formaları dəyişmir. `POST /networks/{id}/sync` cavabında `added`, `skipped`, `errors` (həmişə massiv) və `total` açarları qalır.
- Kod şərhləri ingiliscədir.
- Commit mesajlarında `Co-Authored-By`, `Claude`, `Anthropic` sözləri **yazılmır**.
- Host-da Go yoxdur. Go və shell testləri Docker ilə işlədilir (WSL docker shim). Git Bash-dan çağıranda `MSYS_NO_PATHCONV=1` məcburidir, əks halda `/mnt/c/...` yolları pozulur.
- Repo yolu WSL-də: `/mnt/c/Users/Administrator/Desktop/NovusGate`.

**Test əmrləri (lokal):**
```bash
# Go
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go test ./...
# Center
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
# Shell
MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/deployments/docker:/w -w /w ubuntu:24.04 bash tests/setup-firewall_test.sh
```

## Review Focus

1. **iptables versiyasına görə çıxış formatı fərqlidir.** Yeni iptables-də `-n` protokolu rəqəmlə (`6`/`17`) göstərə bilər, `opt` sütunu (`--`) isə olmaya bilər. Close Port hər iki formatda yalnız öz qaydasını tapmalıdır. Test: Task 2.
2. **sshd portu müxtəlif mənbələrdən gəlir.** `sshd -T` işləməyə bilər, `SSH_CONNECTION` olmaya bilər, `SSH_PORT` səhv dəyər ola bilər. 22 həmişə açıq qalmalı, aşkarlanan portlar da əlavə olunmalıdır. Test: Task 5.
3. **Expiry sərhəd anı.** `expires_at == now` olanda `enrichNode`-dakı qaydaya uyğun gəlməlidir: `now.After(expires)` ödənəndə expired sayılır. `ExpiresAt == nil`, status `expired`, boş açar, nil IP halları da yoxlanılır. Test: Task 3.
4. **Əvvəlki uğursuz install-dan qalıqlar.** `wg0.conf` var, amma `.env` yoxdur. Bu halda guard yenidən quraşdırmanı **bloklamamalıdır**. Test: Task 8.
5. **Reinstall zamanı DB qovluğu.** Fayllar postgres istifadəçisinə məxsus ola bilər, yolda boşluq ola bilər. `server/data` və `admin-vpn.conf` bayt-bayt saxlanmalıdır. Test: Task 7.

---

### Task 1: CI və LF sətir sonluqları

**Files:**
- Create: `.gitattributes`
- Create: `.github/workflows/ci.yml`
- Modify: `NovusGate Center/package.json` (`scripts`)

**Interfaces:**
- Consumes: —
- Produces: CI-da `go`, `web`, `center` və `shell` job-ları. Sonrakı tapşırıqlar öz testlərini bu job-lara əlavə olunmuş qovluqlara yazır: `server/...`, `NovusGate Center/test/`, `server/deployments/docker/tests/`.

- [ ] **Step 1: Baseline-ı yoxla, dəyişiklikdən əvvəl**

```bash
cd /c/Users/Administrator/Desktop/NovusGate
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 sh -c 'go build ./... && go test ./...'
# web: build a copy inside the container so the Windows node_modules is never replaced by Linux binaries
MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/web:/app:ro node:20-bookworm sh -c 'mkdir /tmp/w && tar -C /app --exclude=node_modules -cf - . | tar -C /tmp/w -xf - && cd /tmp/w && npm ci --no-audit --no-fund && npx tsc --noEmit'
node --check "NovusGate Center/server.js"
```
Expected: Go build keçir və `no test files` yazır; `tsc` 0 xəta; `node --check` səssiz keçir.
Hər hansı biri uğursuz olsa, **DAYAN** və çıxışı istifadəçiyə göstər. Mövcud xətaları bu planda düzəltmə: bu, scope-dan kənardır.

- [ ] **Step 2: `.gitattributes` yarat**

```gitattributes
# Shell scripts run on Linux; CRLF breaks bash.
*.sh text eol=lf
```

- [ ] **Step 3: Mövcud `.sh` fayllarını LF ilə yenidən checkout et**

```bash
git add .gitattributes
git commit -m "chore: force LF line endings for shell scripts"
rm server/deployments/docker/setup-firewall.sh
git checkout -- server/deployments/docker/setup-firewall.sh
git ls-files --eol server/deployments/docker/setup-firewall.sh
```
Expected: `i/lf    w/lf    attr/text eol=lf`.

- [ ] **Step 4: Center-ə test skripti əlavə et**

`NovusGate Center/package.json` faylında `scripts` bölməsi belə olmalıdır:
```json
    "scripts": {
        "start": "node server.js",
        "test": "node --test test/*.test.js"
    },
```

- [ ] **Step 5: CI workflow yarat** (`.github/workflows/ci.yml`)

```yaml
name: ci

on:
  push:
  pull_request:

jobs:
  go:
    runs-on: ubuntu-24.04
    defaults:
      run:
        working-directory: server
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: server/go.mod
      - run: go build ./...
      - run: go test ./...

  web:
    runs-on: ubuntu-24.04
    defaults:
      run:
        working-directory: web
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: web/package-lock.json
      - run: npm ci
      - run: npx tsc --noEmit

  center:
    runs-on: ubuntu-24.04
    defaults:
      run:
        working-directory: NovusGate Center
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: node --check server.js
      - run: node --test test/*.test.js

  shell:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: bash server/deployments/docker/tests/setup-firewall_test.sh
```
Qeyd: `center` və `shell` job-ları test faylları yaranana qədər (Task 5 və Task 6) qırmızı olacaq. Bu gözlənilir. Ona görə branch Task 6-dan əvvəl push edilmir.

- [ ] **Step 6: YAML sintaksisini yoxla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate:/r -w /r python:3.12-slim sh -c 'pip -q install pyyaml && python -c "import yaml;yaml.safe_load(open(\".github/workflows/ci.yml\"));print(\"ok\")"'
```
Expected: `ok`

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/ci.yml "NovusGate Center/package.json"
git commit -m "chore: add CI for server, web, center and shell tests"
```

---

### Task 2: Close Port yalnız öz qaydasını silsin (A6)

**Files:**
- Modify: `server/internal/controlplane/api/rest/firewall_handlers.go` (`findRuleLineNumber`, hazırda ~465–497 sətirlər)
- Test: `server/internal/controlplane/api/rest/firewall_portmatch_test.go`

**Interfaces:**
- Consumes: —
- Produces: `findRuleLineNumber(output string, protocol string, port int, target string) int`. İmza dəyişmir, çağıran yalnız `handleFirewallClosePort`-dur.

- [ ] **Step 1: Uğursuz testi yaz**

```go
package rest

import "testing"

// Output of `iptables -L INPUT -n -v --line-numbers` (classic format, with the opt column).
const inputWithOpt = `Chain INPUT (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1      120  9000 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
2     5000  300K ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
3       10   600 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
4        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpts:51820:51900
5        3   180 ACCEPT     tcp  --  wg0    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3007
6        0     0 ACCEPT     tcp  --  wg+    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080
7        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3007
8        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3
9        0     0 ACCEPT     tcp  --  *      *       203.0.113.5          0.0.0.0/0            tcp dpt:8443
`

// Newer iptables: numeric protocol and no opt column.
const inputNumericNoOpt = `Chain INPUT (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot in     out     source               destination
1        0     0 ACCEPT     6    wg0    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3007
2        0     0 ACCEPT     6    *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3
3        0     0 ACCEPT     17   *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:5353
`

func TestFindRuleLineNumber(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		protocol string
		port     int
		want     int
	}{
		{"exact port only, never a prefix of 3007", inputWithOpt, "tcp", 3, 8},
		{"interface-scoped admin rule is not touched", inputWithOpt, "tcp", 3007, 0},
		{"80 does not match 8080", inputWithOpt, "tcp", 80, 0},
		{"source-restricted rule created by Open Port", inputWithOpt, "tcp", 8443, 9},
		{"port range rule is never matched by a single port", inputWithOpt, "udp", 51820, 0},
		{"ssh rule is found (protection is checked by the caller)", inputWithOpt, "tcp", 22, 3},
		{"numeric protocol without opt column", inputNumericNoOpt, "tcp", 3, 2},
		{"numeric udp without opt column", inputNumericNoOpt, "udp", 5353, 3},
		{"numeric format keeps interface protection", inputNumericNoOpt, "tcp", 3007, 0},
		{"short lines do not panic", "1 0 0 ACCEPT\n2 0 0", "tcp", 3, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findRuleLineNumber(tc.output, tc.protocol, tc.port, "ACCEPT")
			if got != tc.want {
				t.Fatalf("findRuleLineNumber(%s, %d) = %d, want %d", tc.protocol, tc.port, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go test ./internal/controlplane/api/rest/ -run TestFindRuleLineNumber -v
```
Expected: FAIL. Konkret olaraq: `exact port only` → `got 5, want 8`; `short lines do not panic` → panic (`index out of range`).

- [ ] **Step 3: `findRuleLineNumber`-i əvəz et**

Köhnə funksiyanı tam sil və yerinə bunu yaz:
```go
// protoNumbers maps protocol names to the numeric form newer iptables prints with -n.
var protoNumbers = map[string]string{"tcp": "6", "udp": "17"}

// isOptColumn reports whether a field is the iptables "opt" column, which
// newer iptables versions omit from `-L -n -v` output.
func isOptColumn(field string) bool {
	return field == "--" || field == "-f" || field == "!f"
}

// findRuleLineNumber returns the line number of an INPUT rule created by
// handleFirewallOpenPort (no input-interface restriction) for the given
// protocol and port, or 0 if none matches. Port matching is exact, so
// closing port 3 never touches a rule for 3007, and port ranges never match.
func findRuleLineNumber(output string, protocol string, port int, target string) int {
	wantPort := "dpt:" + strconv.Itoa(port)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		// num pkts bytes target prot [opt] in out source destination [options...]
		if len(fields) < 9 {
			continue
		}
		lineNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if fields[3] != target {
			continue
		}
		if fields[4] != protocol && fields[4] != protoNumbers[protocol] {
			continue
		}
		inIdx := 5
		if isOptColumn(fields[5]) {
			inIdx = 6
		}
		optionsIdx := inIdx + 4
		if len(fields) <= optionsIdx {
			continue
		}
		// Open Port never sets an input interface; interface-scoped rules
		// (wg0 admin panel, wg+ API) belong to the installer and must stay.
		if fields[inIdx] != "*" {
			continue
		}
		for _, opt := range fields[optionsIdx:] {
			if opt == wantPort {
				return lineNum
			}
		}
	}
	return 0
}
```

- [ ] **Step 4: Testi işlət və keçdiyini gör**

Step 2-dəki əmrin eynisini işlət.
Expected: `PASS`, 10 alt-test.

- [ ] **Step 5: Bütün paketi yoxla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 sh -c 'go build ./... && go test ./...'
```
Expected: `ok` və build xətası yoxdur.

- [ ] **Step 6: Commit**

```bash
git add server/internal/controlplane/api/rest/firewall_handlers.go server/internal/controlplane/api/rest/firewall_portmatch_test.go
git commit -m "fix: match close-port rules exactly and skip interface rules"
```

---

### Task 3: Startup-da peer-ləri DB-dən bərpa et; Sync vaxtı bitmiş node-ları qaytarmasın (A3, B11 qismən)

**Files:**
- Create: `server/internal/controlplane/api/rest/peer_restore.go`
- Test: `server/internal/controlplane/api/rest/peer_restore_test.go`
- Modify: `server/internal/controlplane/api/rest/handlers.go`:
  - `loadNetworks` — `for _, network := range networks` dövrünün sonu, hazırda ~190-cı sətir
  - `handleSyncPeers` — hazırda ~1561–1616

**Interfaces:**
- Consumes: `wireguard.PeerStatus`, `models.Node`, `(*wireguard.Manager).AddPeer(publicKey, allowedIPs string) error`, `(*wireguard.Manager).GetPeers() (map[string]wireguard.PeerStatus, error)`, `store.ListNodes(ctx, networkID) ([]*models.Node, error)`
- Produces:
  - `type peerAdder interface { AddPeer(publicKey, allowedIPs string) error }`
  - `func isNodeActive(node *models.Node, now time.Time) bool`
  - `func restorePeers(mgr peerAdder, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) (int, []string)` — ikinci qiymət heç vaxt `nil` deyil.

- [ ] **Step 1: Uğursuz testi yaz** (`peer_restore_test.go`)

```go
package rest

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

type fakePeerAdder struct {
	added []string
	fail  map[string]bool
}

func (f *fakePeerAdder) AddPeer(publicKey, allowedIPs string) error {
	if f.fail[publicKey] {
		return errors.New("wg set failed")
	}
	f.added = append(f.added, publicKey+" "+allowedIPs)
	return nil
}

func testNode(name, key, ip string, status models.NodeStatus, expires *time.Time) *models.Node {
	return &models.Node{Name: name, PublicKey: key, VirtualIP: net.ParseIP(ip), Status: status, ExpiresAt: expires}
}

func TestRestorePeersAddsOnlyActiveMissingNodes(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	exact := now

	nodes := []*models.Node{
		testNode("active", "KEY_ACTIVE", "10.99.0.3", models.NodeStatusOnline, nil),
		testNode("pending-future", "KEY_FUTURE", "10.99.0.4", models.NodeStatusPending, &future),
		testNode("live-already", "KEY_LIVE", "10.99.0.5", models.NodeStatusOnline, nil),
		testNode("expired-by-time", "KEY_PAST", "10.99.0.6", models.NodeStatusOnline, &past),
		testNode("expired-by-status", "KEY_DISABLED", "10.99.0.7", models.NodeStatusExpired, nil),
		testNode("no-key", "", "10.99.0.8", models.NodeStatusOnline, nil),
		testNode("no-ip", "KEY_NOIP", "", models.NodeStatusOnline, nil),
		// Same boundary as enrichNode: expired only when now.After(expires_at).
		testNode("expires-exactly-now", "KEY_EXACT", "10.99.0.9", models.NodeStatusOnline, &exact),
	}
	live := map[string]wireguard.PeerStatus{"KEY_LIVE": {PublicKey: "KEY_LIVE"}}

	f := &fakePeerAdder{}
	added, errs := restorePeers(f, nodes, live, now)

	want := []string{"KEY_ACTIVE 10.99.0.3/32", "KEY_FUTURE 10.99.0.4/32", "KEY_EXACT 10.99.0.9/32"}
	if !reflect.DeepEqual(f.added, want) {
		t.Fatalf("added peers = %v, want %v", f.added, want)
	}
	if added != 3 {
		t.Fatalf("added = %d, want 3", added)
	}
	if errs == nil || len(errs) != 0 {
		t.Fatalf("errs = %#v, want empty non-nil slice", errs)
	}
}

func TestRestorePeersReportsFailuresAndContinues(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	nodes := []*models.Node{
		testNode("broken", "KEY_BROKEN", "10.99.0.3", models.NodeStatusOnline, nil),
		testNode("fine", "KEY_FINE", "10.99.0.4", models.NodeStatusOnline, nil),
	}
	f := &fakePeerAdder{fail: map[string]bool{"KEY_BROKEN": true}}

	added, errs := restorePeers(f, nodes, nil, now)

	if added != 1 || len(errs) != 1 {
		t.Fatalf("added=%d errs=%v, want 1 and 1", added, errs)
	}
	if errs[0] != "failed to add broken: wg set failed" {
		t.Fatalf("errs[0] = %q", errs[0])
	}
}
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go test ./internal/controlplane/api/rest/ -run TestRestorePeers -v
```
Expected: FAIL — `undefined: restorePeers`.

- [ ] **Step 3: `peer_restore.go`-nu yaz**

```go
package rest

import (
	"fmt"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// peerAdder is the subset of wireguard.Manager needed to restore peers.
type peerAdder interface {
	AddPeer(publicKey, allowedIPs string) error
}

// isNodeActive reports whether a node may hold a WireGuard peer at time now.
// The expiry boundary matches enrichNode: a node is expired once now is after expires_at.
func isNodeActive(node *models.Node, now time.Time) bool {
	if node.PublicKey == "" || node.VirtualIP == nil {
		return false
	}
	if node.Status == models.NodeStatusExpired {
		return false
	}
	if node.ExpiresAt != nil && !node.ExpiresAt.IsZero() && now.After(*node.ExpiresAt) {
		return false
	}
	return true
}

// restorePeers adds every active node that is missing from the live interface.
// It returns the number of peers added and one message per failed node.
func restorePeers(mgr peerAdder, nodes []*models.Node, live map[string]wireguard.PeerStatus, now time.Time) (int, []string) {
	added := 0
	errs := []string{}
	for _, node := range nodes {
		if !isNodeActive(node, now) {
			continue
		}
		if _, ok := live[node.PublicKey]; ok {
			continue
		}
		if err := mgr.AddPeer(node.PublicKey, node.VirtualIP.String()+"/32"); err != nil {
			errs = append(errs, fmt.Sprintf("failed to add %s: %v", node.Name, err))
			continue
		}
		added++
	}
	return added, errs
}
```

- [ ] **Step 4: Testi işlət və keçdiyini gör**

Step 2-dəki əmrin eynisini işlət. Expected: `PASS` (2 test).

- [ ] **Step 5: `loadNetworks`-a bərpanı qoş**

`handlers.go`-da `loadNetworks` funksiyasında `if err == nil && len(peers) > 0 { ... }` blokunun bağlanan `}` mötərizəsindən **sonra**, `for _, network := range networks` dövrünün bağlanan `}` mötərizəsindən **əvvəl** bunu əlavə et:
```go
		// Restore DB peers missing from the interface. Runtime peers are not
		// written to wgN.conf (SaveConfig = false), so a host reboot drops them.
		dbNodes, err := s.store.ListNodes(ctx, network.ID)
		if err != nil {
			fmt.Printf("Warning: cannot restore peers for %s: %v\n", network.InterfaceName, err)
			continue
		}
		livePeers, err := mgr.GetPeers()
		if err != nil {
			fmt.Printf("Warning: cannot read peers of %s: %v\n", network.InterfaceName, err)
			continue
		}
		restored, restoreErrs := restorePeers(mgr, dbNodes, livePeers, time.Now())
		if restored > 0 || len(restoreErrs) > 0 {
			fmt.Printf("Restored %d peers on %s (%d errors)\n", restored, network.InterfaceName, len(restoreErrs))
		}
		for _, e := range restoreErrs {
			fmt.Printf("Warning: %s\n", e)
		}
```

- [ ] **Step 6: `handleSyncPeers`-i eyni funksiyaya keçir**

`handleSyncPeers`-də `// Get current WireGuard peers` şərhindən funksiyanın sonuna qədər olan hissəni bununla əvəz et:
```go
	// Get current WireGuard peers
	currentPeers, err := mgr.GetPeers()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get WireGuard peers: "+err.Error())
		return
	}

	// Expired or disabled nodes are not re-added.
	added, errs := restorePeers(mgr, nodes, currentPeers, time.Now())

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"added":   added,
		"skipped": len(nodes) - added - len(errs),
		"errors":  errs,
		"total":   len(nodes),
	})
}
```
**Kontrakt qeydi:** açarlar və tiplər eynidir. `skipped` indi "artıq mövcud olan **və ya** aktiv olmayan" node-ları sayır.

- [ ] **Step 7: Bütün paketi yoxla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 sh -c 'go build ./... && go vet ./internal/controlplane/api/rest/ && go test ./...'
```
Expected: build və testlər keçir. `go vet`-in bu paketdəki **köhnə** xəbərdarlıqları ola bilər. Onları qeyd et, düzəltmə. Yalnız yeni yazılmış fayllarda xəbərdarlıq qalmamalıdır.

- [ ] **Step 8: Commit**

```bash
git add server/internal/controlplane/api/rest/peer_restore.go server/internal/controlplane/api/rest/peer_restore_test.go server/internal/controlplane/api/rest/handlers.go
git commit -m "fix: restore active peers on startup and skip expired on sync"
```

---

### Task 4: Reboot-dan sonra konteynerlər özü qalxsın (A3)

**Files:**
- Modify: `server/deployments/docker/docker-compose.yml`

**Interfaces:**
- Consumes: Task 3 (control-plane qalxanda peer-ləri bərpa edir)
- Produces: —

- [ ] **Step 1: Mövcud vəziyyətin uğursuz olduğunu təsdiqlə**

```bash
grep -c "restart: unless-stopped" server/deployments/docker/docker-compose.yml
```
Expected: `0`

- [ ] **Step 2: Hər 3 xidmətə restart siyasəti əlavə et**

- `container_name: novusgate-postgres` sətrindən sonra
- `container_name: novusgate-control-plane` sətrindən sonra
- `container_name: novusgate-web` sətrindən sonra

eyni girinti ilə bu sətri əlavə et:
```yaml
    restart: unless-stopped
```
Qeyd: host reboot olanda postgres-in healthcheck-i `depends_on` vasitəsilə gözlənilmir. Control-plane DB hazır olmadan qalxarsa, `failed to connect to database` ilə çıxacaq və restart siyasəti onu yenidən başladacaq. Bu, gözlənilən davranışdır.

- [ ] **Step 3: Compose faylını validasiya et**

```bash
cd /c/Users/Administrator/Desktop/NovusGate
grep -c "restart: unless-stopped" server/deployments/docker/docker-compose.yml
docker compose --env-file server/deployments/docker/.env.example -f server/deployments/docker/docker-compose.yml config --quiet && echo valid
```
Expected: `3` və `valid`. Əgər `ADMIN_PASSWORD is required` xətası çıxsa, `.env.example`-dakı dəyər boşdur. Bu halda müvəqqəti `server/deployments/docker/.env.ci` faylı yarat (`ADMIN_PASSWORD=ci`), əmri onunla işlət və sonra faylı sil.

- [ ] **Step 4: Commit**

```bash
git add server/deployments/docker/docker-compose.yml
git commit -m "fix: restart NovusGate containers automatically after reboot"
```

---

### Task 5: Firewall skripti SSH portunu bağlamasın (A5)

**Files:**
- Modify: `server/deployments/docker/setup-firewall.sh` (tam yenidən yazılır, qaydalar eyni qalır)
- Test: `server/deployments/docker/tests/setup-firewall_test.sh`

**Interfaces:**
- Consumes: Task 1 (`.gitattributes` LF)
- Produces: `setup-firewall.sh` mənbə kimi (source) yüklənəndə `detect_ssh_ports` və `apply_rules` funksiyalarını verir. Birbaşa işlədiləndə əvvəlki kimi `main`-i icra edir. Env: `SSH_PORT` (istəyə bağlı).

- [ ] **Step 1: Uğursuz testi yaz** (`tests/setup-firewall_test.sh`)

```bash
#!/bin/bash
# Tests for setup-firewall.sh. Run from anywhere: bash server/deployments/docker/tests/setup-firewall_test.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../setup-firewall.sh"
FAILURES=0

fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

if ! grep -q '^apply_rules()' "$SCRIPT"; then
  echo "FAIL: setup-firewall.sh has no apply_rules function"
  exit 1
fi

# run_case <sshd -T output or "none"> <SSH_PORT> <SSH_CONNECTION>
# Prints the path of a log with one line per iptables call.
run_case() {
  local sshd_out="$1" ssh_port="$2" ssh_conn="$3"
  local stub
  stub="$(mktemp -d)"
  printf '#!/bin/bash\necho "$*" >> "%s/iptables.log"\n' "$stub" > "$stub/iptables"
  chmod +x "$stub/iptables"
  if [ "$sshd_out" != "none" ]; then
    printf '%s\n' "$sshd_out" > "$stub/sshd.out"
    printf '#!/bin/bash\ncat "%s/sshd.out"\n' "$stub" > "$stub/sshd"
    chmod +x "$stub/sshd"
  fi
  (
    export PATH="$stub:/usr/bin:/bin"
    unset SSH_PORT SSH_CONNECTION
    if [ -n "$ssh_port" ]; then export SSH_PORT="$ssh_port"; fi
    if [ -n "$ssh_conn" ]; then export SSH_CONNECTION="$ssh_conn"; fi
    # shellcheck source=../setup-firewall.sh
    source "$SCRIPT"
    apply_rules > /dev/null
  )
  echo "$stub/iptables.log"
}

line_of() { grep -n -x -F -- "$2" "$1" | head -n1 | cut -d: -f1; }

assert_rule() {
  if [ -z "$(line_of "$1" "$2")" ]; then fail "$3: missing '$2'"; fi
}

assert_drop_last() {
  local log="$1" name="$2"
  local first last drop
  first="$(head -n1 "$log")"
  last="$(tail -n1 "$log")"
  [ "$first" = "-P INPUT ACCEPT" ] || fail "$name: first call is '$first', want '-P INPUT ACCEPT'"
  [ "$last" = "-P INPUT DROP" ] || fail "$name: last call is '$last', want '-P INPUT DROP'"
  drop="$(line_of "$log" "-P INPUT DROP")"
  [ "$drop" = "$(wc -l < "$log" | tr -d ' ')" ] || fail "$name: INPUT DROP is not the final call"
}

# Case 1: sshd listens on 2222 and 22
log="$(run_case $'port 2222\nport 22' "" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 2222 -j ACCEPT" "sshd ports"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "sshd ports"
assert_drop_last "$log" "sshd ports"

# Case 2: no sshd binary, port taken from the current SSH session
log="$(run_case none "" "203.0.113.9 51000 198.51.100.4 2200")"
assert_rule "$log" "-A INPUT -p tcp --dport 2200 -j ACCEPT" "SSH_CONNECTION"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "SSH_CONNECTION"

# Case 3: nothing detected -> 22 only, still safe ordering
log="$(run_case none "" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 22 -j ACCEPT" "fallback"
assert_drop_last "$log" "fallback"

# Case 4: invalid SSH_PORT is ignored, valid one is used
log="$(run_case none "abc" "")"
if grep -q -- "--dport abc" "$log"; then fail "invalid SSH_PORT was used"; fi
log="$(run_case none "2022" "")"
assert_rule "$log" "-A INPUT -p tcp --dport 2022 -j ACCEPT" "SSH_PORT"

# Case 5: every original NovusGate rule is still present
log="$(run_case none "" "")"
for rule in \
  "-A INPUT -i lo -j ACCEPT" \
  "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" \
  "-A INPUT -p udp --dport 51820:51900 -j ACCEPT" \
  "-A INPUT -i wg0 -p tcp --dport 3007 -j ACCEPT" \
  "-A INPUT -i wg+ -p tcp --dport 8080 -j ACCEPT" \
  "-A INPUT -i wg+ -p tcp --dport 8443 -j ACCEPT" \
  "-A INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT" \
  "-A INPUT -p tcp --dport 3007 -j DROP" \
  "-A INPUT -p tcp --dport 5432 -j DROP" \
  "-A INPUT -p icmp -j ACCEPT" \
  "-P FORWARD ACCEPT" \
  "-P OUTPUT ACCEPT" \
  "-F" \
  "-X"; do
  assert_rule "$log" "$rule" "original rules"
done

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES failure(s)"
  exit 1
fi
echo "OK"
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/deployments/docker:/w -w /w ubuntu:24.04 bash tests/setup-firewall_test.sh
```
Expected: `FAIL: setup-firewall.sh has no apply_rules function`, exit 1.

- [ ] **Step 3: `setup-firewall.sh`-ı yenidən yaz**

```bash
#!/bin/bash
set -e

# setup-firewall.sh
# Configures iptables to secure NovusGate admin access via VPN

# detect_ssh_ports prints every TCP port SSH must stay reachable on, one per line.
# Sources: port 22 (always, as before), SSH_PORT env, the port of the current
# SSH session (SSH_CONNECTION) and the ports reported by `sshd -T`.
detect_ssh_ports() {
  {
    echo 22
    if [ -n "${SSH_PORT:-}" ]; then echo "$SSH_PORT"; fi
    if [ -n "${SSH_CONNECTION:-}" ]; then echo "${SSH_CONNECTION##* }"; fi
    if command -v sshd > /dev/null 2>&1; then
      sshd -T 2> /dev/null | awk '$1 == "port" {print $2}'
    fi
  } | grep -E '^[0-9]+$' | sort -un
}

install_persistence() {
  # Install iptables-persistent if not present
  if ! dpkg -l | grep -q iptables-persistent; then
    echo "[FIREWALL] Installing iptables-persistent..."
    # Non-interactive installation
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get update -qq && apt-get install -y iptables-persistent
  fi
}

apply_rules() {
  echo "[FIREWALL] Applying rules..."

  # 1. Accept while the chain is rebuilt, so a failure part-way through can
  #    never leave INPUT=DROP without the SSH rule (lockout).
  iptables -P INPUT ACCEPT
  iptables -F
  iptables -X

  # 2. Default Policies (INPUT switches to DROP at the very end)
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  # 3. Allow Loopback
  iptables -A INPUT -i lo -j ACCEPT

  # 4. Allow Established/Related
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # 5. Allow SSH (Critical) on every port sshd uses
  local port
  for port in $(detect_ssh_ports); do
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done

  # 6. Allow WireGuard Range
  iptables -A INPUT -p udp --dport 51820:51900 -j ACCEPT  # wg0-wg80 (NovusGate Range)

  # 7. Allow Admin Services ONLY from wg0 (Admin Network)
  iptables -A INPUT -i wg0 -p tcp --dport 3007 -j ACCEPT   # Web Dashboard

  # 8. Allow All VPN Networks (wg+) to access API/gRPC
  # Nodes in any network need to talk to the control plane
  iptables -A INPUT -i wg+ -p tcp --dport 8080 -j ACCEPT   # API
  iptables -A INPUT -i wg+ -p tcp --dport 8443 -j ACCEPT   # gRPC

  # 9. Optional: Allow Database access only from Admin (wg0)
  iptables -A INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT

  # 10. Explicitly DROP public access to Admin Services (Safety Net)
  iptables -A INPUT -p tcp --dport 3007 -j DROP
  iptables -A INPUT -p tcp --dport 5432 -j DROP
  # Note: 8080 and 8443 are allowed via wg+, but should be dropped from public/eth0 if not intended.
  # For now, we rely on Default DROP policy for public interfaces.

  # 11. Allow ICMP (Ping)
  iptables -A INPUT -p icmp -j ACCEPT

  # 12. Default DROP only after every allow rule is in place
  iptables -P INPUT DROP
}

restart_docker_stack() {
  # Restart Docker to recreate DOCKER chain
  echo "[FIREWALL] Restarting Docker to restore networking..."
  systemctl restart docker

  # Wait for Docker to be ready
  sleep 5

  # Restart NovusGate containers (only if .env exists)
  echo "[FIREWALL] Restarting NovusGate containers..."
  if [ -f "/opt/NovusGate/server/deployments/docker/.env" ]; then
    cd /opt/NovusGate
    docker-compose -f server/deployments/docker/docker-compose.yml up -d
  else
    echo "[FIREWALL] Warning: .env not found, skipping container restart"
    echo "[FIREWALL] Containers will be started by the installer script"
  fi
}

main() {
  echo "[FIREWALL] Configuring iptables rules..."
  install_persistence
  apply_rules
  echo "[FIREWALL] Saving rules..."
  netfilter-persistent save
  restart_docker_stack
  echo "[FIREWALL] Done! Admin ports are now secured behind VPN."
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
```

- [ ] **Step 4: Testi işlət və keçdiyini gör**

Step 2-dəki əmrin eynisini işlət. Expected: `OK`, exit 0.

- [ ] **Step 5: Sintaksis və LF yoxlaması**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/deployments/docker:/w -w /w ubuntu:24.04 bash -n setup-firewall.sh && echo syntax-ok
git ls-files --eol server/deployments/docker/setup-firewall.sh server/deployments/docker/tests/setup-firewall_test.sh
```
Expected: `syntax-ok`; hər iki fayl üçün `w/lf`.

- [ ] **Step 6: Commit**

```bash
git add server/deployments/docker/setup-firewall.sh server/deployments/docker/tests/setup-firewall_test.sh
git commit -m "fix: keep custom SSH ports open and set INPUT DROP last"
```

---

### Task 6: Center skriptlərini moduldan çıxar və test bünövrəsi qur

**Files:**
- Create: `NovusGate Center/lib/scripts.js` (`server.js`-in 847–1568 sətirləri dəyişmədən köçürülür)
- Modify: `NovusGate Center/server.js` (847–1568 sətirləri silinir, yuxarıya `require` əlavə olunur)
- Create: `NovusGate Center/test/helpers.js` (test olmayan ortaq köməkçilər)
- Test: `NovusGate Center/test/scripts.test.js`

**Interfaces:**
- Consumes: Task 1 (`npm test`)
- Produces:
  - `require('./lib/scripts')` → `{ GENERATE_INSTALL_SCRIPT(config), GENERATE_REINSTALL_SCRIPT(config), UNINSTALL_SCRIPT, UPDATE_SCRIPT, DATABASE_MIGRATE_SCRIPT }`
  - `require('./helpers')` → `{ sampleConfig, generateAll(config) }`. Test faylları bir-birini **require etmir**, əks halda `node --test` testləri ikiqat işlədir.

- [ ] **Step 1: Köməkçini və uğursuz testi yaz**

`test/helpers.js`:
```js
const scripts = require('../lib/scripts');

const sampleConfig = {
  adminUsername: 'admin',
  adminPassword: '',
  networkName: 'Admin',
  networkCidr: '10.99.0.0/24',
  vpnIp: '10.99.0.1',
  dbName: 'novusgate',
  dbUser: 'novusgate',
  dbPassword: '',
};

function generateAll(config) {
  return {
    install: scripts.GENERATE_INSTALL_SCRIPT(config),
    reinstall: scripts.GENERATE_REINSTALL_SCRIPT(config),
    uninstall: scripts.UNINSTALL_SCRIPT,
    update: scripts.UPDATE_SCRIPT,
    migrate: scripts.DATABASE_MIGRATE_SCRIPT,
  };
}

module.exports = { sampleConfig, generateAll };
```

`test/scripts.test.js`:
```js
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { sampleConfig, generateAll } = require('./helpers');

function bashSyntax(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-script-'));
  const file = path.join(dir, 'script.sh');
  fs.writeFileSync(file, script);
  return spawnSync('bash', ['-n', file], { encoding: 'utf8' });
}

for (const [name, script] of Object.entries(generateAll(sampleConfig))) {
  test(`${name} script is valid bash`, () => {
    const result = bashSyntax(script);
    assert.strictEqual(result.status, 0, result.stderr);
  });
}
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
```
Expected: FAIL — `Cannot find module '../lib/scripts'`.

- [ ] **Step 3: Sərhədləri yoxla**

```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center"
sed -n '847p;849p;1568p;1569p' server.js
```
Expected (bu sırada):
```
// ============ INSTALL SCRIPTS ============
const GENERATE_INSTALL_SCRIPT = (config) => `
`;
function createProjectArchive() {
```
Sərhədlər uyğun deyilsə, **DAYAN**: fayl dəyişib və sətir nömrələri yenidən tapılmalıdır.

- [ ] **Step 4: Bloku dəyişmədən köçür**

```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center"
mkdir -p lib
{
  sed -n '847,1568p' server.js
  printf '\nmodule.exports = {\n  GENERATE_INSTALL_SCRIPT,\n  GENERATE_REINSTALL_SCRIPT,\n  UNINSTALL_SCRIPT,\n  UPDATE_SCRIPT,\n  DATABASE_MIGRATE_SCRIPT,\n};\n'
} > lib/scripts.js
sed -i '847,1568d' server.js
```

- [ ] **Step 5: `server.js`-də modulu yüklə**

`server.js`-də `const fail2banModule = require('./modules/fail2ban'); // Import Fail2ban Module` sətrindən sonra bunu əlavə et:
```js
const {
  GENERATE_INSTALL_SCRIPT,
  GENERATE_REINSTALL_SCRIPT,
  UNINSTALL_SCRIPT,
  UPDATE_SCRIPT,
  DATABASE_MIGRATE_SCRIPT,
} = require('./lib/scripts');
```

- [ ] **Step 6: Testləri və yüklənməni yoxla**

```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center"
node --check server.js && node --check lib/scripts.js && echo syntax-ok
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
git diff --stat -- server.js lib/scripts.js
```
Expected:
- `syntax-ok`
- 5 test PASS. Əgər hər hansı skript `bash -n`-dən keçmirsə, bu, **mövcud** baqdır: DAYAN və istifadəçiyə bildir.
- `server.js`-də təxminən 722 silinmiş və 7 əlavə olunmuş sətir.

- [ ] **Step 7: Center-in işə düşdüyünü yoxla**

```bash
# Runs on a copy so the local node_modules / data are not touched.
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app:ro" node:20-bookworm sh -c 'mkdir /tmp/c && tar -C /app --exclude=node_modules --exclude=data -cf - . | tar -C /tmp/c -xf - && cd /tmp/c && npm ci --omit=dev --no-audit --no-fund > /dev/null && PORT=3999 timeout 5 node server.js; echo "exit=$?"'
```
Expected: `NovusGate Center: http://localhost:3999` yazılır, sonra `exit=124` (timeout prosesi dayandırıb). `ReferenceError` və ya `Cannot find module` olmamalıdır.

- [ ] **Step 8: Commit**

```bash
git add "NovusGate Center/lib/scripts.js" "NovusGate Center/server.js" "NovusGate Center/test/helpers.js" "NovusGate Center/test/scripts.test.js"
git commit -m "refactor: move Center install scripts into lib/scripts.js"
```

---

### Task 7: Reinstall DB-ni və admin VPN config-i silməsin (A1)

**Files:**
- Modify: `NovusGate Center/lib/scripts.js` (`GENERATE_REINSTALL_SCRIPT`)
- Test: `NovusGate Center/test/reinstall.test.js`

**Interfaces:**
- Consumes: Task 6 (`lib/scripts.js`, `generateAll`, `sampleConfig`)
- Produces: `scripts.CLEAN_INSTALL_DIR_FN`. Bu, bash funksiya mətnidir: `clean_install_dir <dir>`.

- [ ] **Step 1: Uğursuz testi yaz** (`test/reinstall.test.js`)

```js
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { sampleConfig } = require('./helpers');

function makeTree() {
  // A space in the path guards against unquoted variables.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ng install '));
  const dir = path.join(root, 'NovusGate');
  const write = (rel, content) => {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  };
  write('server/data/postgres/PG_VERSION', '16\n');
  write('server/data/postgres/base/1/1259', 'binary');
  write('server/go.mod', 'module x\n');
  write('server/deployments/docker/.env', 'DB_PASSWORD=x\n');
  write('web/index.html', '<html>');
  write('admin-vpn.conf', '[Interface]\n');
  write('data/keep.txt', 'k');
  write('stale.txt', 's');
  return dir;
}

function runClean(dir) {
  return spawnSync('bash', ['-c', `${scripts.CLEAN_INSTALL_DIR_FN}\nclean_install_dir "$1"`, 'bash', dir], { encoding: 'utf8' });
}

test('clean_install_dir keeps the database, top-level data and admin-vpn.conf', () => {
  const dir = makeTree();
  const result = runClean(dir);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(fs.existsSync(dir), 'install dir itself must survive');
  assert.strictEqual(fs.readFileSync(path.join(dir, 'server/data/postgres/PG_VERSION'), 'utf8'), '16\n');
  assert.strictEqual(fs.readFileSync(path.join(dir, 'server/data/postgres/base/1/1259'), 'utf8'), 'binary');
  assert.ok(fs.existsSync(path.join(dir, 'admin-vpn.conf')));
  assert.ok(fs.existsSync(path.join(dir, 'data/keep.txt')));
  assert.ok(!fs.existsSync(path.join(dir, 'server/go.mod')));
  assert.ok(!fs.existsSync(path.join(dir, 'server/deployments')));
  assert.ok(!fs.existsSync(path.join(dir, 'web')));
  assert.ok(!fs.existsSync(path.join(dir, 'stale.txt')));
});

test('clean_install_dir on a missing directory is a no-op', () => {
  const missing = path.join(os.tmpdir(), `ng-missing-${process.pid}`);
  const result = runClean(missing);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(!fs.existsSync(missing));
});

test('reinstall script uses clean_install_dir instead of the unsafe find', () => {
  const script = scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig);
  assert.match(script, /clean_install_dir "\$INSTALL_DIR"/);
  assert.doesNotMatch(script, /-maxdepth 1 ! -name 'data' ! -name '\.'/);
});

test('reinstall script backs up and restores web/.env', () => {
  const script = scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig);
  assert.match(script, /cp "\$INSTALL_DIR\/web\/\.env" \/tmp\/NovusGate\.web\.env\.bak/);
  assert.match(script, /mv \/tmp\/NovusGate\.web\.env\.bak web\/\.env/);
});
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
```
Expected: `reinstall.test.js` testləri FAIL. Məsələn `clean_install_dir: command not found` və ya regex uyğun gəlmir.

- [ ] **Step 3: Funksiyanı `lib/scripts.js`-in əvvəlinə əlavə et**

`// ============ INSTALL SCRIPTS ============` sətrindən sonra:
```js
// Bash function that empties the install dir while keeping persistent state:
// the Postgres data directory (server/data, bind-mounted by docker-compose),
// a legacy top-level data/ directory and the admin VPN client config.
const CLEAN_INSTALL_DIR_FN = `
clean_install_dir() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  find "$dir" -mindepth 1 -maxdepth 1 ! -name 'server' ! -name 'data' ! -name 'admin-vpn.conf' -exec rm -rf {} +
  if [ -d "$dir/server" ]; then
    find "$dir/server" -mindepth 1 -maxdepth 1 ! -name 'data' -exec rm -rf {} +
  fi
}
`;
```

- [ ] **Step 4: `GENERATE_REINSTALL_SCRIPT`-də təmizləmə blokunu əvəz et**

Bu blok:
```
# Remove files but KEEP the data directory
if [ -d "$INSTALL_DIR" ]; then
  echo "Cleaning files (preserving data)..."
  find "$INSTALL_DIR" -maxdepth 1 ! -name 'data' ! -name '.' -exec rm -rf {} +
fi
```
bununla əvəz olunur:
```
# Remove files but KEEP the database (server/data) and admin-vpn.conf
${CLEAN_INSTALL_DIR_FN}
echo "Cleaning files (preserving server/data and admin-vpn.conf)..."
clean_install_dir "$INSTALL_DIR"
```

- [ ] **Step 5: `web/.env`-i də saxla**

Eyni skriptdə bu sətrin:
```
  cp "$INSTALL_DIR/server/deployments/docker/.env" /tmp/NovusGate.env.bak
```
ardınca, eyni `if` blokunun içində əlavə et:
```
  if [ -f "$INSTALL_DIR/web/.env" ]; then
    cp "$INSTALL_DIR/web/.env" /tmp/NovusGate.web.env.bak
  fi
```
Bu sətrin ardınca:
```
  mv /tmp/NovusGate.env.bak server/deployments/docker/.env
```
əlavə et:
```
  if [ -f /tmp/NovusGate.web.env.bak ]; then
    mkdir -p web
    mv /tmp/NovusGate.web.env.bak web/.env
  fi
```

- [ ] **Step 6: Export-a əlavə et və testləri işlət**

`module.exports` obyektinə `CLEAN_INSTALL_DIR_FN,` əlavə et. Sonra:
```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
```
Expected: bütün testlər PASS, `reinstall script is valid bash` də daxil olmaqla.

- [ ] **Step 7: Commit**

```bash
git add "NovusGate Center/lib/scripts.js" "NovusGate Center/test/reinstall.test.js"
git commit -m "fix: keep database and admin VPN config on reinstall"
```

---

### Task 8: Quraşdırılmış serverdə "Install" sistemi sındırmasın (A2)

**Files:**
- Modify: `NovusGate Center/lib/scripts.js` (`GENERATE_INSTALL_SCRIPT`)
- Modify: `NovusGate Center/server.js` (install route-unun `stream.on('close')` handler-i)
- Test: `NovusGate Center/test/install-guard.test.js`

**Interfaces:**
- Consumes: Task 6
- Produces: `scripts.EXIT_ALREADY_INSTALLED === 3`, `scripts.ALREADY_INSTALLED_GUARD` (bash mətni, `$INSTALL_DIR` dəyişənini gözləyir).

- [ ] **Step 1: Uğursuz testi yaz** (`test/install-guard.test.js`)

```js
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { sampleConfig } = require('./helpers');

function runGuard(installDir) {
  const body = `INSTALL_DIR="$1"\n${scripts.ALREADY_INSTALLED_GUARD}\necho passed`;
  return spawnSync('bash', ['-c', body, 'bash', installDir], { encoding: 'utf8' });
}

test('guard lets a fresh server through', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-guard-'));
  const result = runGuard(dir);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.match(result.stdout, /passed/);
});

test('leftovers of a failed install without .env do not block a retry', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-guard-'));
  fs.mkdirSync(path.join(dir, 'server/deployments/docker'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'admin-vpn.conf'), '[Interface]\n');
  const result = runGuard(dir);
  assert.strictEqual(result.status, 0, result.stderr);
});

test('guard stops when NovusGate is already installed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-guard-'));
  fs.mkdirSync(path.join(dir, 'server/deployments/docker'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'server/deployments/docker/.env'), 'DB_PASSWORD=x\n');
  const result = runGuard(dir);
  assert.strictEqual(result.status, scripts.EXIT_ALREADY_INSTALLED);
  assert.strictEqual(scripts.EXIT_ALREADY_INSTALLED, 3);
  assert.match(result.stdout, /already installed/);
  assert.doesNotMatch(result.stdout, /passed/);
});

test('guard runs before any package installation or secret generation', () => {
  const script = scripts.GENERATE_INSTALL_SCRIPT(sampleConfig);
  const guard = script.indexOf('is already installed in');
  assert.ok(guard > -1, 'guard missing from install script');
  assert.ok(guard < script.indexOf('apt-get'), 'guard must run before apt-get');
  assert.ok(guard < script.indexOf('generate_secret()'), 'guard must run before secrets are generated');
  assert.ok(guard < script.indexOf('wg genkey'), 'guard must run before wg0 keys are generated');
});
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

Task 7 Step 6-dakı əmri işlət. Expected: `install-guard.test.js` FAIL (`ALREADY_INSTALLED_GUARD` undefined).

- [ ] **Step 3: Guard-ı `lib/scripts.js`-ə əlavə et**

`CLEAN_INSTALL_DIR_FN`-dən sonra:
```js
// Exit code of the install script when NovusGate is already installed.
const EXIT_ALREADY_INSTALLED = 3;

// A fresh install regenerates the database password and the wg0 server key,
// which would lock the control plane out of the existing database and break
// every VPN client. Existing installs must use Update or Reinstall instead.
const ALREADY_INSTALLED_GUARD = `
if [ -f "$INSTALL_DIR/server/deployments/docker/.env" ]; then
  echo "[ERROR] NovusGate is already installed in $INSTALL_DIR."
  echo "Use Update (keeps everything) or Reinstall (keeps database and .env) instead."
  rm -f /tmp/NovusGate.tar.gz
  exit ${EXIT_ALREADY_INSTALLED}
fi
`;
```
`GENERATE_INSTALL_SCRIPT`-də `NC='\\033[0m'` sətrindən dərhal sonra əlavə et:
```
${ALREADY_INSTALLED_GUARD}
```
`module.exports`-a `EXIT_ALREADY_INSTALLED,` və `ALREADY_INSTALLED_GUARD,` əlavə et.

- [ ] **Step 4: Center-də statusu "error"-a çevirmə**

`server.js`-də require-ə `EXIT_ALREADY_INSTALLED`-i əlavə et. Install route-unda `stream.on('close', (code) => {` daxilində bu sətirləri:
```js
        // Update server status
        server.status = code === 0 ? 'installed' : 'error';
        server.installedAt = new Date().toISOString();
```
bununla əvəz et:
```js
        // A refused install on an already-installed server keeps its status.
        const alreadyInstalled = code === EXIT_ALREADY_INSTALLED && !update && !reinstall && !migrateOnly;
        if (!alreadyInstalled) {
          // Update server status
          server.status = code === 0 ? 'installed' : 'error';
          server.installedAt = new Date().toISOString();
        }
```

- [ ] **Step 5: Testləri işlət**

```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center" && node --check server.js && echo syntax-ok
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
```
Expected: `syntax-ok`, bütün testlər PASS.

- [ ] **Step 6: Commit**

```bash
git add "NovusGate Center/lib/scripts.js" "NovusGate Center/server.js" "NovusGate Center/test/install-guard.test.js"
git commit -m "fix: refuse fresh install over an existing NovusGate"
```

---

### Task 9: Quraşdırma xətası Center-i çökdürməsin (A4)

**Files:**
- Create: `NovusGate Center/lib/sse.js`
- Modify: `NovusGate Center/server.js` (install route-unun `catch` bloku; fayl sonunda proses səviyyəli handler)
- Test: `NovusGate Center/test/sse.test.js`

**Interfaces:**
- Consumes: —
- Produces: `endWithError(res, err): void`. Header-lər göndərilibsə, xətanı SSE event kimi göndərir, əks halda 500 JSON qaytarır.

- [ ] **Step 1: Uğursuz testi yaz** (`test/sse.test.js`)

```js
const test = require('node:test');
const assert = require('node:assert');
const { endWithError } = require('../lib/sse');

function fakeRes(headersSent) {
  return {
    headersSent,
    chunks: [],
    statusCode: 200,
    body: undefined,
    ended: false,
    write(chunk) { this.chunks.push(chunk); return true; },
    end() { this.ended = true; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; this.ended = true; return this; },
  };
}

const event = (chunk) => JSON.parse(chunk.replace(/^data: /, ''));

test('after SSE headers are flushed the error is sent as stream events', () => {
  const res = fakeRes(true);
  endWithError(res, new Error('All configured authentication methods failed'));
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.chunks.length, 2);
  assert.deepStrictEqual(event(res.chunks[0]), { text: '[ERROR] All configured authentication methods failed\n', stderr: true });
  assert.deepStrictEqual(event(res.chunks[1]), { done: true, success: false });
  assert.ok(res.ended);
});

test('before headers are sent it answers with 500 JSON', () => {
  const res = fakeRes(false);
  endWithError(res, new Error('boom'));
  assert.strictEqual(res.statusCode, 500);
  assert.deepStrictEqual(res.body, { error: 'boom' });
  assert.strictEqual(res.chunks.length, 0);
});

test('non-Error values are reported as text', () => {
  const res = fakeRes(true);
  endWithError(res, 'timeout');
  assert.deepStrictEqual(event(res.chunks[0]), { text: '[ERROR] timeout\n', stderr: true });
});
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

Task 7 Step 6-dakı əmri işlət. Expected: FAIL — `Cannot find module '../lib/sse'`.

- [ ] **Step 3: `lib/sse.js`-i yaz**

```js
// Ends an install/update request after a failure. Once the SSE headers are
// flushed, Express can no longer send a JSON error (it throws
// ERR_HTTP_HEADERS_SENT), so the error goes out as a final stream event.
function endWithError(res, err) {
  const message = err instanceof Error ? err.message : String(err);
  if (res.headersSent) {
    res.write(`data: ${JSON.stringify({ text: `[ERROR] ${message}\n`, stderr: true })}\n\n`);
    res.write(`data: ${JSON.stringify({ done: true, success: false })}\n\n`);
    res.end();
    return;
  }
  res.status(500).json({ error: message });
}

module.exports = { endWithError };
```

- [ ] **Step 4: `server.js`-də istifadə et**

Require-lərə əlavə et:
```js
const { endWithError } = require('./lib/sse');
```
Install route-unun `catch (err)` blokundakı bu sətri:
```js
    res.status(500).json({ error: err.message });
```
bununla əvəz et:
```js
    endWithError(res, err);
```
Faylın sonunda, `server.listen(PORT, ...)` blokundan əvvəl əlavə et:
```js
// One failed request must not take down installs running for other servers.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
});
```

- [ ] **Step 5: Testləri işlət**

```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center" && node --check server.js && echo syntax-ok
MSYS_NO_PATHCONV=1 docker run --rm -v "/mnt/c/Users/Administrator/Desktop/NovusGate/NovusGate Center:/app" -w /app node:20-bookworm sh -c 'node --test test/*.test.js'
```
Expected: `syntax-ok`, bütün testlər PASS.

- [ ] **Step 6: Commit**

```bash
git add "NovusGate Center/lib/sse.js" "NovusGate Center/server.js" "NovusGate Center/test/sse.test.js"
git commit -m "fix: report install errors on the stream instead of crashing"
```

---

### Task 10: Center-in kiçik baqları — binary adı, konteyner adları, admin-vpn.conf (B17, B18, B19)

**Files:**
- Modify: `NovusGate Center/lib/scripts.js`
- Modify: `NovusGate Center/server.js` (`/status` route-unda `grep NovusGate`)
- Modify: `NovusGate Center/public/index.html` (`.replace('NovusGate-', '')`)
- Test: `NovusGate Center/test/center-fixes.test.js`

**Interfaces:**
- Consumes: Task 6
- Produces: —

- [ ] **Step 1: Uğursuz testi yaz** (`test/center-fixes.test.js`)

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { generateAll, sampleConfig } = require('./helpers');

const all = generateAll(sampleConfig);

test('migrate calls the binary built by Dockerfile.control-plane', () => {
  for (const [name, script] of Object.entries(all)) {
    assert.doesNotMatch(script, /NovusGate-server/, `${name} uses the wrong binary name`);
  }
  assert.match(all.migrate, /\.\/novusgate-server migrate/);
  assert.match(all.update, /\.\/novusgate-server migrate/);
});

test('container lookups match the lowercase compose names', () => {
  for (const [name, script] of Object.entries(all)) {
    assert.doesNotMatch(script, /--filter name=NovusGate/, `${name} filters by the wrong name`);
    assert.doesNotMatch(script, /grep NovusGate/, `${name} greps the wrong name`);
  }
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.doesNotMatch(server, /grep NovusGate/);
});

test('update keeps admin-vpn.conf', () => {
  assert.match(all.update, /--exclude='admin-vpn\.conf'/);
});
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

Task 7 Step 6-dakı əmri işlət. Expected: 3 test FAIL.

- [ ] **Step 3: Binary adını düzəlt**

`lib/scripts.js`-də `./NovusGate-server` mətnini `./novusgate-server` ilə əvəz et. 3 yer var: install-dakı şərhə alınmış `INIT_OUTPUT` sətri, `UPDATE_SCRIPT` və `DATABASE_MIGRATE_SCRIPT`.
```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center"
sed -i 's#\./NovusGate-server#./novusgate-server#g' lib/scripts.js
grep -c "novusgate-server" lib/scripts.js
```
Expected: `3`

- [ ] **Step 4: Konteyner adlarını düzəlt**

```bash
cd "/c/Users/Administrator/Desktop/NovusGate/NovusGate Center"
sed -i 's#--filter name=NovusGate#--filter name=novusgate#g; s#grep NovusGate#grep -i novusgate#g' lib/scripts.js server.js
grep -n "name=novusgate\|grep -i novusgate" lib/scripts.js server.js
```
Expected:
- `lib/scripts.js`-də 3 `--filter name=novusgate` (install pre-flight-da 2, uninstall-da 1) və 4 `grep -i novusgate` (install, reinstall, uninstall, update).
- `server.js`-də 1 `grep -i novusgate` (`/status` route-u).

`public/index.html`-də:
```js
${(c.name || 'unknown').replace('NovusGate-', '')}
```
bununla əvəz et:
```js
${(c.name || 'unknown').replace(/^novusgate-/i, '')}
```

- [ ] **Step 5: Update `admin-vpn.conf`-u silməsin**

`UPDATE_SCRIPT`-də `--exclude='*.log' \\` sətrindən sonra əlavə et:
```
    --exclude='admin-vpn.conf' \\
```

- [ ] **Step 6: Testləri işlət**

Task 7 Step 6-dakı əmri işlət. Expected: bütün testlər PASS, `update script is valid bash` də daxil olmaqla.

- [ ] **Step 7: Commit**

```bash
git add "NovusGate Center/lib/scripts.js" "NovusGate Center/server.js" "NovusGate Center/public/index.html" "NovusGate Center/test/center-fixes.test.js"
git commit -m "fix: correct migrate binary, container names and keep admin-vpn.conf"
```

---

### Task 11: Staging-də qəbul və sənədləşdirmə

**Files:**
- Create: `docs/active-context.md`
- Create: `docs/runbooks/p1-staging-acceptance.md`

**Interfaces:**
- Consumes: Task 1–10
- Produces: P2 üçün başlanğıc nöqtəsi.

- [ ] **Step 1: Bütün avtomatik testləri bir dəfə də işlət**

Global Constraints-dəki 3 test əmrini işlət.
Expected: Go `ok`, Center bütün testlər PASS, shell `OK`.

- [ ] **Step 2: Runbook-u yaz** (`docs/runbooks/p1-staging-acceptance.md`)

```markdown
# P1 Staging Acceptance

Staging: təzə Ubuntu 24.04 VM, root SSH. Hər addımın nəticəsini (əmr + çıxış) bu faylın sonuna yaz.

1. Center ilə Install (port 22). Gözlənilən: log `INSTALLATION COMPLETE`, `docker ps` 3 konteyner `Up`.
2. Panel → yeni şəbəkə (wg1) + 2 peer (biri 1 saatlıq). Bir client qoş.
3. `sudo reboot`. Boot-dan sonra:
   - `docker ps` → 3 konteyner `Up` (restart policy)
   - `wg show wg1 peers` → hər iki aktiv peer var
   - client yenidən qoşulur, panel açılır
4. Center → Reinstall. Gözlənilən:
   - `ls /opt/NovusGate/server/data/postgres/PG_VERSION` var
   - `ls /opt/NovusGate/admin-vpn.conf` var
   - panelə köhnə admin parolu ilə giriş olur, şəbəkələr və peer-lər yerindədir
5. Center → Install (quraşdırılmış serverdə). Gözlənilən: log `[ERROR] NovusGate is already installed`, Center-də status `installed` qalır.
6. Panel → Open Port tcp 3, sonra Close Port tcp 3. `iptables -S INPUT` → `-i wg0 ... --dport 3007 -j ACCEPT` hələ də var.
7. Ayrıca VM: `/etc/ssh/sshd_config` → `Port 2222`, Center-də port 2222 ilə Install. Gözlənilən: install-dan sonra və reboot-dan sonra `ssh -p 2222` işləyir.
8. Center-də səhv parollu server → Install. Gözlənilən: log `[ERROR] ...`, Center konteyneri işləməyə davam edir (`docker ps` uptime sıfırlanmayıb).
9. Center → Update, sonra Migrate. Gözlənilən: `admin-vpn.conf` yerindədir, Migrate `✅ Database updated!` yazır.
```

- [ ] **Step 3: Runbook-u icra et**

Staging VM olmasa, **bu addımı icra etmə**. Hesabata `Staging qəbulu icra olunmadı, səbəb: VM yoxdur` yaz və istifadəçidən VM istə. Əl ilə nəticə uydurma.

- [ ] **Step 4: `docs/active-context.md` yarat**

```markdown
# Active Context

## Son Sessiya
- **Tarix:** <icra tarixi>
- **Tapşırıq:** P1 Stabilizasiya (`docs/superpowers/plans/2026-10-13-p1-stabilization.md`)
- **Nəticə:** <Task 1–10 commit-ləri; staging qəbulunun nəticəsi>
- **Davam:** P2 Backend nüvəsi planı yazılmalıdır

## Son Dəyişikliklər
| Tarix | Dəyişiklik | Fayllar | Səbəb |
|---|---|---|---|
| <tarix> | Close Port dəqiq uyğunluq | firewall_handlers.go | A6 lockout |
| <tarix> | Startup-da peer bərpası, sync expired-i qaytarmır | peer_restore.go, handlers.go | A3, B11 |
| <tarix> | Konteyner restart siyasəti | docker-compose.yml | A3 |
| <tarix> | SSH port aşkarlanması, DROP sonda | setup-firewall.sh | A5 |
| <tarix> | Center skriptləri moduldan çıxarıldı | lib/scripts.js, server.js | test oluna bilmə |
| <tarix> | Reinstall DB/admin-vpn.conf saxlayır | lib/scripts.js | A1 |
| <tarix> | Install guard | lib/scripts.js, server.js | A2 |
| <tarix> | SSE xətası crash etmir | lib/sse.js, server.js | A4 |
| <tarix> | Binary/konteyner adı, admin-vpn.conf | lib/scripts.js, server.js, index.html | B17–B19 |
```

- [ ] **Step 5: Commit**

```bash
git add docs/active-context.md docs/runbooks/p1-staging-acceptance.md
git commit -m "docs: add P1 staging runbook and active context"
```
