# P3a — Firewall Mühərriki (nftables): İmplementasiya Planı

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** NovusGate-in öz nftables cədvəli (`table inet novusgate`) üçün mühərrik qurmaq: model, validasiya, kompilyator, SSH qoruması, host aşkarlanması, executor, təsdiqli və avtomatik geri qayıdan tətbiq, DB → model çevirici, `novusgate-server firewall preview`. Hostda **heç nə avtomatik dəyişmir**. İnteqrasiya P3b-dədir.

**Architecture:**
- `internal/netctl/nft` yalnız standart kitabxanadan istifadə edən, təmiz Go paketidir. Kompilyator `nft -f` üçün atomik skript yaradır. `Executor` nft CLI-ni `Runner` interfeysi arxasından çağırır. `SafeApplier` snapshot + host timer (`systemd-run`) + prosesdaxili timer ilə "təsdiqlə, yoxsa geri qayıt" mexanizmini qurur.
- `internal/controlplane/firewall` DB modellərini mühərrik modelinə çevirir.
- Plandakı kodun hamısı yazılmazdan əvvəl prototip kimi sınaqdan keçirilib: `go vet`, testlər, nft 1.0.2/1.0.6/1.0.9-da `nft -c`, kernel-də apply/snapshot/restore.

**Tech Stack:** Go 1.23 (`net/netip`, `testing`), nftables CLI 1.0.2+, systemd (`systemd-run`), Docker (testlər üçün).

**Spec:** `docs/superpowers/specs/2026-10-13-p3-firewall-design.md` (ana spec: `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`)

## Global Constraints

- Yeni Go paketi əlavə olunmur, yalnız standart kitabxana. Alpine image-ə `nftables` sistem paketi əlavə olunur (spec §2).
- Bu planda hostdakı firewall **avtomatik dəyişmir**. Heç bir HTTP handler və startup kodu nft tətbiq etmir. Yeganə yeni giriş nöqtəsi `firewall preview` əmridir və o da yalnız `nft -c` icra edir.
- Cədvəlin adı `inet novusgate`-dir. Başqa cədvəllərə (Docker, fail2ban) toxunulmur.
- Kod şərhləri ingiliscədir. Commit mesajlarında `Co-Authored-By`, `Claude`, `Anthropic` sözləri **yazılmır**.
- Host-da Go yoxdur. Testlər Docker-də işlədilir. Git Bash-dan çağıranda `MSYS_NO_PATHCONV=1` məcburidir. **Docker argumentlərində `$` olmamalıdır**, çünki WSL shim onu genişləndirir. Shell məntiqi `server/scripts/test-in-docker.sh` faylında olur.
- Fokuslu test əmri (kernel olmadan):
  `MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go test ./internal/netctl/nft/ -run <TestName> -v`
- Tam yoxlama (kernel daxil):
  `MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 bash scripts/test-in-docker.sh`

## Review Focus

1. **Köhnə nftables versiyası (Ubuntu 22.04: 1.0.2).** Kompilyatorun çıxışı ən köhnə dəstəklənən versiyada da yüklənməlidir. Task 1 Step 7 bunu ubuntu:22.04 image-ində `nft -c` ilə yoxlayır.
2. **İstifadəçi mətninin nft-yə "inject" olunması.** Interfeys adında və ya ID-də `"` / `accept` / `#` olarsa, mətn nft sintaksisini poza bilər. `Validate` bunu rədd etməlidir. Test: Task 1 `TestValidateRejectsUnsafeInput`.
3. **Üst-üstə düşən set elementləri.** `/24` blok və onun içində `/32`, WireGuard aralığının içində olan listen port. nft interval set-də overlap qəbul etmir, kompilyator bunları birləşdirməli və ya atmalıdır. Test: Task 1 golden + `TestMergeRanges`.
4. **Təsdiq gəlməsə, geri qayıtma.** Control plane çökəndə və ya host timer qurula bilməyəndə sistem heç vaxt qorumasız tətbiq etməməlidir. Test: Task 4 `TestSafeApplyRefusesWithoutSafetyNet` və digərləri.
5. **SSH portunun aşkarlanmaması.** `sshd -T` işləmirsə, sistem port uydurmamalı və rədd etməlidir. Test: Task 2 `TestCheckProtection`, Task 5 `TestDetectHost`.

---

### Task 1: nftables modeli, validasiya və kompilyator

**Files:**
- Create: `server/internal/netctl/nft/model.go`
- Create: `server/internal/netctl/nft/validate.go`
- Create: `server/internal/netctl/nft/compile.go`
- Create: `server/scripts/test-in-docker.sh`
- Test: `server/internal/netctl/nft/compile_test.go`
- Test fixture: `server/internal/netctl/nft/testdata/full.nft`

**Interfaces:**
- Consumes: —
- Produces:
  - tiplər `Protocol` (`TCP`, `UDP`, `ICMP`, `All`), `PortRange{From,To uint16}` + `String()`, `Service`, `BlockedEntry`, `PortForward`, `VPNNetwork`, `VPNRule`, `Ruleset`;
  - sabitlər `TableName`, `AdminInterface`, `VPNInterfacePattern`;
  - dəyişənlər `LegacyWireGuardRange`, `AdminPorts`, `APIPorts`;
  - `func Validate(rs Ruleset) error`;
  - `func Compile(rs Ruleset, now time.Time) (string, error)`;
  - paket daxili köməkçilər `contains`, `networkFor`, `ifaceRe` (Task 2 və 3 istifadə edir);
  - test köməkçiləri `fullRuleset()`, `testNow` (Task 2–4 testləri istifadə edir).

- [ ] **Step 1: Test skriptini yarat** (`server/scripts/test-in-docker.sh`)

```bash
#!/bin/bash
# Runs the Go checks and tests inside a Linux container that has nftables,
# including the kernel checks (NFT_CHECK=1). Needs CAP_NET_ADMIN, e.g. from
# the repo root on the Windows dev machine:
#   MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v gomod:/go/pkg/mod \
#     -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src \
#     golang:1.23 bash scripts/test-in-docker.sh
# Keep shell logic in this file: the WSL docker shim expands "$" in arguments.
set -euo pipefail

if ! command -v nft > /dev/null 2>&1; then
  apt-get update -qq > /dev/null
  apt-get install -y -qq nftables > /dev/null
fi

# Only check paths that exist yet, so the script works while P3a is built task by task.
fmt_paths=()
vet_pkgs=(./internal/controlplane/api/rest/ ./cmd/control-plane/)
for p in ./internal/netctl ./internal/controlplane/firewall ./cmd/control-plane/firewall_cmd.go; do
  if [ -e "$p" ]; then
    fmt_paths+=("$p")
  fi
done
if [ -d ./internal/netctl ]; then vet_pkgs+=(./internal/netctl/...); fi
if [ -d ./internal/controlplane/firewall ]; then vet_pkgs+=(./internal/controlplane/firewall/); fi

if [ "${#fmt_paths[@]}" -gt 0 ]; then
  unformatted=$(gofmt -l "${fmt_paths[@]}")
  if [ -n "$unformatted" ]; then
    echo "gofmt needed:"
    echo "$unformatted"
    exit 1
  fi
fi

go vet "${vet_pkgs[@]}"
go build ./...
NFT_CHECK=1 go test ./... -count=1
```

- [ ] **Step 2: Uğursuz testi və golden faylı yaz**

`server/internal/netctl/nft/compile_test.go`:
```go
package nft

import (
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func fullRuleset() Ruleset {
	inOneHour := testNow.Add(time.Hour)
	expired := testNow.Add(-time.Minute)
	return Ruleset{
		SSHPorts:        []uint16{2222, 22, 22},
		EgressInterface: "eth0",
		Networks: []VPNNetwork{
			{Interface: "wg1", CIDR: netip.MustParsePrefix("10.20.0.0/24"), ListenPort: 51821},
			{Interface: "wg0", CIDR: netip.MustParsePrefix("10.99.0.0/24"), ListenPort: 51820},
			{Interface: "wg2", CIDR: netip.MustParsePrefix("10.30.0.0/24"), ListenPort: 51950},
		},
		Services: []Service{
			{ID: "https", Proto: TCP, Ports: PortRange{443, 443}},
			{ID: "office-rdp", Proto: TCP, Ports: PortRange{3389, 3389},
				Sources: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}},
			{ID: "vpn-dns", Proto: UDP, Ports: PortRange{53, 53}, Interface: "wg1"},
		},
		Blocked: []BlockedEntry{
			{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			{Prefix: netip.MustParsePrefix("198.51.100.7/32")}, // covered by the /24
			{Prefix: netip.MustParsePrefix("192.0.2.9/32"), Expires: &inOneHour},
			{Prefix: netip.MustParsePrefix("192.0.2.10/32"), Expires: &expired}, // already expired
			{Prefix: netip.MustParsePrefix("2001:db8:bad::/48")},
		},
		Forwards: []PortForward{
			{ID: "home-cam", Proto: TCP, PublicPort: 8081, TargetIP: netip.MustParseAddr("10.20.0.5"), TargetPort: 80},
		},
		VPNRules: []VPNRule{
			{ID: "block-ssh-a-b", Src: netip.MustParsePrefix("10.20.0.0/24"), Dst: netip.MustParsePrefix("10.30.0.0/24"),
				Proto: TCP, Ports: []PortRange{{22, 22}}, Action: "drop"},
			{ID: "a-to-b-web", Src: netip.MustParsePrefix("10.20.0.0/24"), Dst: netip.MustParsePrefix("10.30.0.0/24"),
				Proto: TCP, Ports: []PortRange{{80, 80}, {8000, 8100}}, Action: "accept"},
			{ID: "any-ping", Src: netip.MustParsePrefix("0.0.0.0/0"), Dst: netip.MustParsePrefix("10.30.0.10/32"),
				Proto: ICMP, Action: "accept"},
		},
		Egress: []netip.Addr{netip.MustParseAddr("10.20.0.7"), netip.MustParseAddr("10.20.0.6")},
	}
}

func TestCompileGolden(t *testing.T) {
	got, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	golden := filepath.Join("testdata", "full.nft")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if got != string(want) {
		t.Fatalf("compiled ruleset differs from %s\n--- got ---\n%s", golden, got)
	}
}

func TestCompileKeyBehaviour(t *testing.T) {
	got, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	mustContain := []string{
		"elements = { 22, 2222 }",                                 // SSH ports deduplicated and sorted
		"elements = { 51820-51900, 51950 }",                       // legacy range merged with listen ports
		"elements = { 192.0.2.9 timeout 3600s, 198.51.100.0/24 }", // expired and covered entries dropped
		"type filter hook input priority filter - 10; policy drop;",
		`iifname "wg0" tcp dport { 3007, 5432 } accept`,
		`iifname "wg*" tcp dport { 8080, 8443 } accept`,
		`ip saddr { 203.0.113.0/24 } tcp dport 3389 accept comment "svc:office-rdp"`,
		`ip6 saddr { 2001:db8::/32 } tcp dport 3389 accept comment "svc:office-rdp"`,
		`iifname "wg1" udp dport 53 accept comment "svc:vpn-dns"`,
		`iifname "eth0" meta l4proto tcp ct original proto-dst 5432 counter drop`,
		`ip saddr 10.20.0.0/24 ip daddr 10.30.0.0/24 tcp dport { 22 } counter drop comment "rule:block-ssh-a-b"`,
		`ip daddr 10.30.0.10/32 meta l4proto icmp counter accept comment "rule:any-ping"`,
		`iifname "wg0" oifname "wg0" accept`,
		`iifname "eth0" tcp dport 8081 dnat ip to 10.20.0.5:80 comment "fwd:home-cam"`,
		`ip daddr 10.20.0.5 oifname "wg1" tcp dport 80 ct status dnat masquerade comment "fwd:home-cam"`,
		"elements = { 10.20.0.6, 10.20.0.7 }",
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q", s)
		}
	}
	// Rule order matters: the drop for port 22 must precede the broader accept.
	if strings.Index(got, "rule:block-ssh-a-b") > strings.Index(got, "rule:a-to-b-web") {
		t.Error("VPN rules must keep their order")
	}
	if strings.Contains(got, "192.0.2.10") || strings.Contains(got, "198.51.100.7") {
		t.Error("expired or covered blocked entries must not be rendered")
	}
}

func TestValidateRejectsUnsafeInput(t *testing.T) {
	cases := map[string]func(*Ruleset){
		"no ssh ports":               func(r *Ruleset) { r.SSHPorts = nil },
		"injection in egress":        func(r *Ruleset) { r.EgressInterface = `eth0" accept` },
		"injection in service id":    func(r *Ruleset) { r.Services[0].ID = `x" accept #` },
		"public admin port":          func(r *Ruleset) { r.Services[0].Ports = PortRange{8000, 8090} },
		"forward on ssh port":        func(r *Ruleset) { r.Forwards[0].PublicPort = 2222 },
		"forward outside vpn":        func(r *Ruleset) { r.Forwards[0].TargetIP = netip.MustParseAddr("192.168.1.10") },
		"ports with icmp":            func(r *Ruleset) { r.VPNRules[2].Ports = []PortRange{{1, 2}} },
		"unknown action":             func(r *Ruleset) { r.VPNRules[0].Action = "allow" },
		"ipv6 egress":                func(r *Ruleset) { r.Egress = []netip.Addr{netip.MustParseAddr("2001:db8::1")} },
		"forward in wireguard range": func(r *Ruleset) { r.Forwards[0].Proto = UDP; r.Forwards[0].PublicPort = 51830 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rs := fullRuleset()
			mutate(&rs)
			if _, err := Compile(rs, testNow); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestAdminPortAllowedOnVPNInterface(t *testing.T) {
	rs := fullRuleset()
	rs.Services = append(rs.Services, Service{ID: "vpn-alt-api", Proto: TCP, Ports: PortRange{8080, 8080}, Interface: "wg1"})
	if _, err := Compile(rs, testNow); err != nil {
		t.Fatalf("a VPN-only service may use an admin port: %v", err)
	}
}

func TestMergeRanges(t *testing.T) {
	got := rangeElems([]PortRange{{51820, 51900}, {51850, 51850}, {51901, 51901}, {60000, 60000}, {10, 20}})
	want := "10-20, 51820-51901, 60000"
	if strings.Join(got, ", ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

// TestCompiledRulesetLoadsInKernel feeds the compiled script to `nft -c`.
// It runs only when NFT_CHECK=1 and needs the nft binary and CAP_NET_ADMIN.
func TestCompiledRulesetLoadsInKernel(t *testing.T) {
	if os.Getenv("NFT_CHECK") != "1" {
		t.Skip("set NFT_CHECK=1 to validate against the kernel")
	}
	script, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the ruleset: %v\n%s", err, out)
	}
}
```

`server/internal/netctl/nft/testdata/full.nft` (kompilyatorun gözlənilən çıxışı; sonda yeni sətir var, Tab ilə girinti):
```
table inet novusgate
delete table inet novusgate
table inet novusgate {
	set ssh_ports {
		type inet_service
		elements = { 22, 2222 }
	}
	set wg_ports {
		type inet_service
		flags interval
		elements = { 51820-51900, 51950 }
	}
	set blocked_v4 {
		type ipv4_addr
		flags interval, timeout
		elements = { 192.0.2.9 timeout 3600s, 198.51.100.0/24 }
	}
	set blocked_v6 {
		type ipv6_addr
		flags interval, timeout
		elements = { 2001:db8:bad::/48 }
	}
	set egress_v4 {
		type ipv4_addr
		elements = { 10.20.0.6, 10.20.0.7 }
	}
	chain input {
		type filter hook input priority filter - 10; policy drop;
		iif "lo" accept
		ip saddr @blocked_v4 counter drop
		ip6 saddr @blocked_v6 counter drop
		ct state established,related accept
		ct state invalid drop
		tcp dport @ssh_ports accept
		udp dport @wg_ports accept
		iifname "wg0" tcp dport { 3007, 5432 } accept
		iifname "wg*" tcp dport { 8080, 8443 } accept
		tcp dport 443 accept comment "svc:https"
		ip saddr { 203.0.113.0/24 } tcp dport 3389 accept comment "svc:office-rdp"
		ip6 saddr { 2001:db8::/32 } tcp dport 3389 accept comment "svc:office-rdp"
		iifname "wg1" udp dport 53 accept comment "svc:vpn-dns"
		meta l4proto { icmp, ipv6-icmp } accept
		counter comment "default drop"
	}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		ip saddr @blocked_v4 counter drop
		ip6 saddr @blocked_v6 counter drop
		ct state established,related accept
		iifname "eth0" meta l4proto tcp ct original proto-dst 5432 counter drop comment "docker-published postgres"
		iifname "wg*" jump vpn_policy
		oifname "wg*" ct status dnat accept
		oifname "wg*" counter drop
	}
	chain vpn_policy {
		ip saddr 10.20.0.0/24 ip daddr 10.30.0.0/24 tcp dport { 22 } counter drop comment "rule:block-ssh-a-b"
		ip saddr 10.20.0.0/24 ip daddr 10.30.0.0/24 tcp dport { 80, 8000-8100 } counter accept comment "rule:a-to-b-web"
		ip daddr 10.30.0.10/32 meta l4proto icmp counter accept comment "rule:any-ping"
		iifname "wg0" oifname "wg0" accept
		iifname "wg1" oifname "wg1" accept
		iifname "wg2" oifname "wg2" accept
		oifname "eth0" ip saddr @egress_v4 accept
		counter drop comment "vpn default drop"
	}
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" tcp dport 8081 dnat ip to 10.20.0.5:80 comment "fwd:home-cam"
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip daddr 10.20.0.5 oifname "wg1" tcp dport 80 ct status dnat masquerade comment "fwd:home-cam"
		oifname "eth0" ip saddr @egress_v4 masquerade
	}
}
```

- [ ] **Step 3: Testi işlət və uğursuz olduğunu gör**

Global Constraints-dəki fokuslu əmri `-run 'TestCompile|TestValidate|TestMergeRanges|TestAdminPort'` ilə işlət.
Expected: build FAIL — `undefined: Ruleset`, `undefined: Compile`, …

- [ ] **Step 4: Modeli yaz** (`model.go`)

```go
// Package nft compiles NovusGate's firewall model into an nftables script for
// its own table (inet novusgate) and applies it safely.
package nft

import (
	"fmt"
	"net/netip"
	"time"
)

// Protocol is a layer-4 protocol used by the firewall model.
type Protocol string

const (
	TCP  Protocol = "tcp"
	UDP  Protocol = "udp"
	ICMP Protocol = "icmp"
	All  Protocol = "all"
)

// PortRange is an inclusive port range; a single port has From == To.
type PortRange struct {
	From uint16
	To   uint16
}

// String renders the range in nft syntax ("443" or "8000-8100").
func (r PortRange) String() string {
	if r.From == r.To {
		return fmt.Sprintf("%d", r.From)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// Service opens a host port in the input chain.
type Service struct {
	ID        string
	Proto     Protocol // tcp or udp
	Ports     PortRange
	Sources   []netip.Prefix // empty means any source
	Interface string         // empty means any interface
}

// BlockedEntry drops all traffic from a prefix until Expires (nil = permanent).
type BlockedEntry struct {
	Prefix  netip.Prefix
	Expires *time.Time
}

// PortForward publishes TargetIP:TargetPort (a VPN node) on PublicPort of the
// egress interface.
type PortForward struct {
	ID         string
	Proto      Protocol // tcp or udp
	PublicPort uint16
	TargetIP   netip.Addr
	TargetPort uint16
}

// VPNNetwork is one WireGuard interface with its subnet and UDP listen port.
type VPNNetwork struct {
	Interface  string
	CIDR       netip.Prefix
	ListenPort uint16
}

// VPNRule controls forwarding between VPN subnets; rules are evaluated in order.
type VPNRule struct {
	ID     string
	Src    netip.Prefix
	Dst    netip.Prefix
	Proto  Protocol
	Ports  []PortRange // only for tcp and udp
	Action string      // accept, drop or reject
}

// Ruleset is the complete desired state of table inet novusgate.
type Ruleset struct {
	SSHPorts        []uint16
	EgressInterface string
	Networks        []VPNNetwork
	Services        []Service
	Blocked         []BlockedEntry
	Forwards        []PortForward
	VPNRules        []VPNRule
	Egress          []netip.Addr // full-tunnel nodes allowed to reach the internet
}

const (
	// TableName is the only nftables table NovusGate owns.
	TableName = "novusgate"
	// AdminInterface carries the admin network (panel and database access).
	AdminInterface = "wg0"
	// VPNInterfacePattern matches every NovusGate WireGuard interface.
	VPNInterfacePattern = "wg*"
)

var (
	// LegacyWireGuardRange is the UDP range the installer has always opened.
	LegacyWireGuardRange = PortRange{From: 51820, To: 51900}
	// AdminPorts are reachable only from the admin interface (panel, database).
	AdminPorts = []uint16{3007, 5432}
	// APIPorts are reachable from every VPN interface (control-plane API, gRPC).
	APIPorts = []uint16{8080, 8443}
)
```

- [ ] **Step 5: Validasiyanı yaz** (`validate.go`)

```go
package nft

import (
	"fmt"
	"regexp"
)

var (
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// reservedPorts can never be opened as public services or used for forwards.
func reservedPorts() map[uint16]bool {
	m := map[uint16]bool{}
	for _, p := range append(append([]uint16{}, AdminPorts...), APIPorts...) {
		m[p] = true
	}
	return m
}

// Validate rejects any ruleset that cannot be compiled safely. Identifiers and
// interface names are restricted so nothing user-supplied can break out of the
// generated nft syntax.
func Validate(rs Ruleset) error {
	if len(rs.SSHPorts) == 0 {
		return fmt.Errorf("at least one SSH port is required")
	}
	for _, p := range rs.SSHPorts {
		if p == 0 {
			return fmt.Errorf("invalid SSH port 0")
		}
	}
	if !ifaceRe.MatchString(rs.EgressInterface) {
		return fmt.Errorf("invalid egress interface %q", rs.EgressInterface)
	}
	for _, n := range rs.Networks {
		if !ifaceRe.MatchString(n.Interface) {
			return fmt.Errorf("invalid network interface %q", n.Interface)
		}
		if !n.CIDR.IsValid() || !n.CIDR.Addr().Is4() {
			return fmt.Errorf("network %s: CIDR must be IPv4", n.Interface)
		}
	}
	reserved := reservedPorts()
	for _, s := range rs.Services {
		if !idRe.MatchString(s.ID) {
			return fmt.Errorf("invalid service id %q", s.ID)
		}
		if s.Proto != TCP && s.Proto != UDP {
			return fmt.Errorf("service %s: protocol must be tcp or udp", s.ID)
		}
		if s.Ports.From == 0 || s.Ports.To < s.Ports.From {
			return fmt.Errorf("service %s: invalid port range %s", s.ID, s.Ports)
		}
		if s.Interface != "" && !ifaceRe.MatchString(s.Interface) {
			return fmt.Errorf("service %s: invalid interface %q", s.ID, s.Interface)
		}
		for _, src := range s.Sources {
			if !src.IsValid() {
				return fmt.Errorf("service %s: invalid source", s.ID)
			}
		}
		if s.Proto == TCP && !isVPNInterface(s.Interface) {
			for p := range reserved {
				if p >= s.Ports.From && p <= s.Ports.To {
					return fmt.Errorf("service %s: port %d is reserved for VPN-only admin services", s.ID, p)
				}
			}
		}
	}
	for _, b := range rs.Blocked {
		if !b.Prefix.IsValid() {
			return fmt.Errorf("invalid blocked prefix")
		}
	}
	for _, f := range rs.Forwards {
		if !idRe.MatchString(f.ID) {
			return fmt.Errorf("invalid forward id %q", f.ID)
		}
		if f.Proto != TCP && f.Proto != UDP {
			return fmt.Errorf("forward %s: protocol must be tcp or udp", f.ID)
		}
		if f.PublicPort == 0 || f.TargetPort == 0 {
			return fmt.Errorf("forward %s: ports must be 1-65535", f.ID)
		}
		if f.Proto == TCP && (reserved[f.PublicPort] || contains(rs.SSHPorts, f.PublicPort)) {
			return fmt.Errorf("forward %s: public port %d is reserved", f.ID, f.PublicPort)
		}
		if f.Proto == UDP && f.PublicPort >= LegacyWireGuardRange.From && f.PublicPort <= LegacyWireGuardRange.To {
			return fmt.Errorf("forward %s: public port %d is in the WireGuard range", f.ID, f.PublicPort)
		}
		if _, ok := networkFor(rs.Networks, f.TargetIP); !ok {
			return fmt.Errorf("forward %s: target %s is not inside any VPN network", f.ID, f.TargetIP)
		}
	}
	for _, r := range rs.VPNRules {
		if !idRe.MatchString(r.ID) {
			return fmt.Errorf("invalid VPN rule id %q", r.ID)
		}
		if !r.Src.IsValid() || !r.Dst.IsValid() || !r.Src.Addr().Is4() || !r.Dst.Addr().Is4() {
			return fmt.Errorf("VPN rule %s: source and destination must be IPv4 prefixes", r.ID)
		}
		switch r.Proto {
		case TCP, UDP:
		case ICMP, All:
			if len(r.Ports) > 0 {
				return fmt.Errorf("VPN rule %s: ports are only allowed for tcp and udp", r.ID)
			}
		default:
			return fmt.Errorf("VPN rule %s: unknown protocol %q", r.ID, r.Proto)
		}
		for _, p := range r.Ports {
			if p.From == 0 || p.To < p.From {
				return fmt.Errorf("VPN rule %s: invalid port range %s", r.ID, p)
			}
		}
		if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
			return fmt.Errorf("VPN rule %s: unknown action %q", r.ID, r.Action)
		}
	}
	for _, a := range rs.Egress {
		if !a.Is4() {
			return fmt.Errorf("egress address %s must be IPv4", a)
		}
	}
	return nil
}

func isVPNInterface(name string) bool {
	return len(name) >= 2 && name[:2] == "wg"
}

func contains(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}
```

- [ ] **Step 6: Kompilyatoru yaz** (`compile.go`)

```go
package nft

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Compile renders rs as an nft script that atomically replaces table
// inet novusgate. The script is valid input for `nft -f` and `nft -c -f`.
// now is used to turn blocked-entry expiry times into remaining timeouts.
func Compile(rs Ruleset, now time.Time) (string, error) {
	if err := Validate(rs); err != nil {
		return "", err
	}
	b := &builder{}
	// Declaring the table first makes the delete succeed on a host where it
	// does not exist yet; the whole file is applied as one transaction.
	b.line(0, "table inet "+TableName)
	b.line(0, "delete table inet "+TableName)
	b.line(0, "table inet "+TableName+" {")
	writeSets(b, rs, now)
	writeInput(b, rs)
	writeForward(b, rs)
	writeVPNPolicy(b, rs)
	writeNAT(b, rs)
	b.line(0, "}")
	return b.String(), nil
}

type builder struct{ strings.Builder }

func (b *builder) line(indent int, s string) {
	b.WriteString(strings.Repeat("\t", indent))
	b.WriteString(s)
	b.WriteString("\n")
}

func (b *builder) set(name, typ string, flags []string, elems []string) {
	b.line(1, "set "+name+" {")
	b.line(2, "type "+typ)
	if len(flags) > 0 {
		b.line(2, "flags "+strings.Join(flags, ", "))
	}
	if len(elems) > 0 {
		b.line(2, "elements = { "+strings.Join(elems, ", ")+" }")
	}
	b.line(1, "}")
}

func writeSets(b *builder, rs Ruleset, now time.Time) {
	b.set("ssh_ports", "inet_service", nil, portElems(rs.SSHPorts))
	b.set("wg_ports", "inet_service", []string{"interval"}, rangeElems(wireGuardRanges(rs)))
	v4, v6 := blockedElems(rs.Blocked, now)
	b.set("blocked_v4", "ipv4_addr", []string{"interval", "timeout"}, v4)
	b.set("blocked_v6", "ipv6_addr", []string{"interval", "timeout"}, v6)
	b.set("egress_v4", "ipv4_addr", nil, addrElems(rs.Egress))
}

func writeInput(b *builder, rs Ruleset) {
	b.line(1, "chain input {")
	b.line(2, "type filter hook input priority filter - 10; policy drop;")
	b.line(2, `iif "lo" accept`)
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	b.line(2, "ct state established,related accept")
	b.line(2, "ct state invalid drop")
	b.line(2, "tcp dport @ssh_ports accept")
	b.line(2, "udp dport @wg_ports accept")
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, AdminInterface, joinPorts(AdminPorts)))
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, VPNInterfacePattern, joinPorts(APIPorts)))
	for _, s := range rs.Services {
		for _, l := range serviceLines(s) {
			b.line(2, l)
		}
	}
	b.line(2, "meta l4proto { icmp, ipv6-icmp } accept")
	b.line(2, `counter comment "default drop"`)
	b.line(1, "}")
}

func serviceLines(s Service) []string {
	var prefix string
	if s.Interface != "" {
		prefix = fmt.Sprintf("iifname %q ", s.Interface)
	}
	tail := fmt.Sprintf("%s dport %s accept comment %q", s.Proto, s.Ports, "svc:"+s.ID)
	if len(s.Sources) == 0 {
		return []string{prefix + tail}
	}
	var v4, v6 []string
	for _, p := range s.Sources {
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	var lines []string
	if len(v4) > 0 {
		lines = append(lines, prefix+"ip saddr { "+strings.Join(v4, ", ")+" } "+tail)
	}
	if len(v6) > 0 {
		lines = append(lines, prefix+"ip6 saddr { "+strings.Join(v6, ", ")+" } "+tail)
	}
	return lines
}

func writeForward(b *builder, rs Ruleset) {
	b.line(1, "chain forward {")
	b.line(2, "type filter hook forward priority filter - 10; policy accept;")
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	b.line(2, "ct state established,related accept")
	// Docker publishes postgres on all addresses and its DNAT bypasses the
	// input chain; only the admin VPN may reach it.
	b.line(2, fmt.Sprintf(`iifname %q meta l4proto tcp ct original proto-dst 5432 counter drop comment "docker-published postgres"`, rs.EgressInterface))
	b.line(2, fmt.Sprintf(`iifname %q jump vpn_policy`, VPNInterfacePattern))
	b.line(2, fmt.Sprintf(`oifname %q ct status dnat accept`, VPNInterfacePattern))
	b.line(2, fmt.Sprintf(`oifname %q counter drop`, VPNInterfacePattern))
	b.line(1, "}")
}

func writeVPNPolicy(b *builder, rs Ruleset) {
	b.line(1, "chain vpn_policy {")
	for _, r := range rs.VPNRules {
		b.line(2, vpnRuleLine(r))
	}
	// Peers of the same network have always been able to talk to each other.
	for _, n := range sortedNetworks(rs.Networks) {
		b.line(2, fmt.Sprintf(`iifname %q oifname %q accept`, n.Interface, n.Interface))
	}
	b.line(2, fmt.Sprintf(`oifname %q ip saddr @egress_v4 accept`, rs.EgressInterface))
	b.line(2, `counter drop comment "vpn default drop"`)
	b.line(1, "}")
}

func vpnRuleLine(r VPNRule) string {
	var parts []string
	if r.Src.Bits() != 0 {
		parts = append(parts, "ip saddr "+r.Src.Masked().String())
	}
	if r.Dst.Bits() != 0 {
		parts = append(parts, "ip daddr "+r.Dst.Masked().String())
	}
	switch r.Proto {
	case TCP, UDP:
		if len(r.Ports) > 0 {
			parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Proto, strings.Join(rangeElems(r.Ports), ", ")))
		} else {
			parts = append(parts, "meta l4proto "+string(r.Proto))
		}
	case ICMP:
		parts = append(parts, "meta l4proto icmp")
	}
	parts = append(parts, "counter", r.Action, fmt.Sprintf("comment %q", "rule:"+r.ID))
	return strings.Join(parts, " ")
}

func writeNAT(b *builder, rs Ruleset) {
	b.line(1, "chain prerouting {")
	b.line(2, "type nat hook prerouting priority dstnat; policy accept;")
	for _, f := range rs.Forwards {
		b.line(2, fmt.Sprintf(`iifname %q %s dport %d dnat ip to %s:%d comment %q`,
			rs.EgressInterface, f.Proto, f.PublicPort, f.TargetIP, f.TargetPort, "fwd:"+f.ID))
	}
	b.line(1, "}")
	b.line(1, "chain postrouting {")
	b.line(2, "type nat hook postrouting priority srcnat; policy accept;")
	for _, f := range rs.Forwards {
		n, _ := networkFor(rs.Networks, f.TargetIP)
		// Masquerade so the node replies through the hub: its AllowedIPs only
		// cover VPN subnets, not the internet client's address.
		b.line(2, fmt.Sprintf(`ip daddr %s oifname %q %s dport %d ct status dnat masquerade comment %q`,
			f.TargetIP, n.Interface, f.Proto, f.TargetPort, "fwd:"+f.ID))
	}
	b.line(2, fmt.Sprintf(`oifname %q ip saddr @egress_v4 masquerade`, rs.EgressInterface))
	b.line(1, "}")
}

func networkFor(networks []VPNNetwork, ip netip.Addr) (VPNNetwork, bool) {
	for _, n := range networks {
		if n.CIDR.Contains(ip) {
			return n, true
		}
	}
	return VPNNetwork{}, false
}

func sortedNetworks(networks []VPNNetwork) []VPNNetwork {
	out := append([]VPNNetwork(nil), networks...)
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

func portElems(ports []uint16) []string {
	seen := map[uint16]bool{}
	var sorted []int
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			sorted = append(sorted, int(p))
		}
	}
	sort.Ints(sorted)
	out := make([]string, len(sorted))
	for i, p := range sorted {
		out[i] = fmt.Sprintf("%d", p)
	}
	return out
}

func joinPorts(ports []uint16) string { return strings.Join(portElems(ports), ", ") }

// wireGuardRanges merges the legacy installer range with every network's
// listen port, so networks beyond 51900 stay reachable.
func wireGuardRanges(rs Ruleset) []PortRange {
	ranges := []PortRange{LegacyWireGuardRange}
	for _, n := range rs.Networks {
		if n.ListenPort != 0 {
			ranges = append(ranges, PortRange{From: n.ListenPort, To: n.ListenPort})
		}
	}
	return mergeRanges(ranges)
}

// mergeRanges returns sorted, non-overlapping, non-adjacent ranges; nft
// rejects overlapping elements in interval sets.
func mergeRanges(in []PortRange) []PortRange {
	rs := append([]PortRange(nil), in...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].From < rs[j].From })
	var out []PortRange
	for _, r := range rs {
		if n := len(out); n > 0 && uint32(r.From) <= uint32(out[n-1].To)+1 {
			if r.To > out[n-1].To {
				out[n-1].To = r.To
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func rangeElems(ranges []PortRange) []string {
	merged := mergeRanges(ranges)
	out := make([]string, len(merged))
	for i, r := range merged {
		out[i] = r.String()
	}
	return out
}

// blockedElems drops expired entries and entries covered by a broader prefix
// (interval sets reject overlaps), then renders the remaining timeouts.
func blockedElems(entries []BlockedEntry, now time.Time) (v4, v6 []string) {
	var active []BlockedEntry
	for _, e := range entries {
		if e.Expires != nil && !e.Expires.After(now) {
			continue
		}
		e.Prefix = e.Prefix.Masked()
		active = append(active, e)
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].Prefix.Bits() != active[j].Prefix.Bits() {
			return active[i].Prefix.Bits() < active[j].Prefix.Bits()
		}
		return active[i].Prefix.Addr().Less(active[j].Prefix.Addr())
	})
	var kept []BlockedEntry
	for _, e := range active {
		covered := false
		for _, k := range kept {
			if k.Prefix.Addr().Is4() == e.Prefix.Addr().Is4() && k.Prefix.Contains(e.Prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, e)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Prefix.Addr().Less(kept[j].Prefix.Addr()) })
	for _, e := range kept {
		el := elemPrefix(e.Prefix)
		if e.Expires != nil {
			secs := int64(math.Ceil(e.Expires.Sub(now).Seconds()))
			el += fmt.Sprintf(" timeout %ds", secs)
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	return v4, v6
}

// elemPrefix renders a host prefix as a bare address, as nft lists it.
func elemPrefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func addrElems(addrs []netip.Addr) []string {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	s := make([]string, len(out))
	for i, a := range out {
		s[i] = a.String()
	}
	return s
}
```

- [ ] **Step 7: Testləri işlət, sonra köhnə nft-də yoxla**

Step 3-dəki əmri təkrar işlət. Expected: `PASS` (golden, key behaviour, validate, merge, admin-port), `TestCompiledRulesetLoadsInKernel` isə SKIP.

Tam yoxlama əmrini işlət (Global Constraints). Expected: `ok …/internal/netctl/nft`, `TestCompiledRulesetLoadsInKernel` PASS.

Ubuntu 22.04-dəki ən köhnə nftables versiyasında yoxla:
```bash
MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v /mnt/c/Users/Administrator/Desktop/NovusGate/server/internal/netctl/nft/testdata:/t ubuntu:22.04 bash -c "apt-get update -qq >/dev/null; apt-get install -y -qq nftables >/dev/null 2>&1; nft --version; nft -c -f /t/full.nft && echo KERNEL-CHECK-OK"
```
Expected: `nftables v1.0.2` və `KERNEL-CHECK-OK`.

- [ ] **Step 8: Commit**

```bash
git add server/internal/netctl/nft/model.go server/internal/netctl/nft/validate.go server/internal/netctl/nft/compile.go server/internal/netctl/nft/compile_test.go server/internal/netctl/nft/testdata/full.nft server/scripts/test-in-docker.sh
git commit -m "feat: add nftables ruleset model, validation and compiler"
```

---

### Task 2: SSH qoruması və host aşkarlama parser-ləri

**Files:**
- Create: `server/internal/netctl/nft/guard.go`
- Create: `server/internal/netctl/nft/detect.go`
- Test: `server/internal/netctl/nft/guard_test.go`
- Test: `server/internal/netctl/nft/detect_test.go`

**Interfaces:**
- Consumes: Task 1 (`Ruleset`, `contains`, `ifaceRe`, `fullRuleset`, `testNow`)
- Produces:
  - `type Protection struct{ SSHPorts []uint16; Addrs []netip.Addr }`;
  - `func CheckProtection(rs Ruleset, p Protection, now time.Time) error`;
  - `func ParseSSHDPorts(out string) []uint16`;
  - `func ParseRouteDevice(out string) (string, error)`.

- [ ] **Step 1: Uğursuz testləri yaz**

`guard_test.go`:
```go
package nft

import (
	"net/netip"
	"testing"
	"time"
)

func TestCheckProtection(t *testing.T) {
	rs := fullRuleset()
	inHour := testNow.Add(time.Hour)
	ok := Protection{SSHPorts: []uint16{22, 2222}, Addrs: []netip.Addr{netip.MustParseAddr("10.99.0.2")}}
	if err := CheckProtection(rs, ok, testNow); err != nil {
		t.Fatalf("valid ruleset rejected: %v", err)
	}
	if err := CheckProtection(rs, Protection{}, testNow); err == nil {
		t.Fatal("no detected SSH port must fail closed")
	}
	if err := CheckProtection(rs, Protection{SSHPorts: []uint16{2200}}, testNow); err == nil {
		t.Fatal("a detected SSH port missing from the ruleset must be refused")
	}
	rs.Blocked = append(rs.Blocked, BlockedEntry{Prefix: netip.MustParsePrefix("10.99.0.0/24"), Expires: &inHour})
	if err := CheckProtection(rs, ok, testNow); err == nil {
		t.Fatal("blocking the operator's own address must be refused")
	}
}
```

`detect_test.go`:
```go
package nft

import "testing"

func TestParsers(t *testing.T) {
	ports := ParseSSHDPorts("port 2222\nport 22\naddressfamily any\nport 22\nport 0\n")
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 2222 {
		t.Fatalf("ParseSSHDPorts = %v", ports)
	}
	dev, err := ParseRouteDevice("8.8.8.8 via 192.0.2.1 dev ens3 src 192.0.2.10 uid 0\n    cache\n")
	if err != nil || dev != "ens3" {
		t.Fatalf("ParseRouteDevice = %q, %v", dev, err)
	}
	if dev, err := ParseRouteDevice("8.8.8.8 dev ppp0 src 10.64.0.2 uid 0"); err != nil || dev != "ppp0" {
		t.Fatalf("route without gateway: %q, %v", dev, err)
	}
	if _, err := ParseRouteDevice("RTNETLINK answers: Network is unreachable"); err == nil {
		t.Fatal("missing device must be an error")
	}
}
```

- [ ] **Step 2: Testləri işlət və uğursuz olduğunu gör**

Fokuslu əmri `-run 'TestCheckProtection|TestParsers'` ilə işlət. Expected: build FAIL — `undefined: Protection`, `undefined: ParseSSHDPorts`.

- [ ] **Step 3: `guard.go`-nu yaz**

```go
package nft

import (
	"fmt"
	"net/netip"
	"time"
)

// Protection lists what a ruleset must never cut off: every port sshd
// listens on and the addresses the operator is connected from right now.
type Protection struct {
	SSHPorts []uint16
	Addrs    []netip.Addr
}

// CheckProtection refuses a ruleset that would lock the operator out. It
// fails closed: with no detected SSH port it refuses rather than guessing.
func CheckProtection(rs Ruleset, p Protection, now time.Time) error {
	if len(p.SSHPorts) == 0 {
		return fmt.Errorf("no SSH port detected; refusing to apply firewall changes")
	}
	for _, port := range p.SSHPorts {
		if !contains(rs.SSHPorts, port) {
			return fmt.Errorf("ruleset does not keep SSH port %d open", port)
		}
	}
	for _, addr := range p.Addrs {
		for _, b := range rs.Blocked {
			if b.Expires != nil && !b.Expires.After(now) {
				continue
			}
			if b.Prefix.Contains(addr) {
				return fmt.Errorf("blocked entry %s would cut off the current session from %s", b.Prefix, addr)
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: `detect.go`-nu yaz**

```go
package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParseSSHDPorts extracts the listening ports from `sshd -T` output.
func ParseSSHDPorts(out string) []uint16 {
	seen := map[uint16]bool{}
	var ports []uint16
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.ToLower(fields[0]) != "port" {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 1 || n > 65535 || seen[uint16(n)] {
			continue
		}
		seen[uint16(n)] = true
		ports = append(ports, uint16(n))
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// ParseRouteDevice returns the interface after "dev" in `ip route get` output,
// e.g. "8.8.8.8 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 0".
func ParseRouteDevice(out string) (string, error) {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			if !ifaceRe.MatchString(fields[i+1]) {
				return "", fmt.Errorf("unexpected interface name %q", fields[i+1])
			}
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no device in route output %q", strings.TrimSpace(out))
}
```

- [ ] **Step 5: Testləri işlət**

Step 2-dəki əmri işlət. Expected: `PASS` (2 test).

- [ ] **Step 6: Commit**

```bash
git add server/internal/netctl/nft/guard.go server/internal/netctl/nft/detect.go server/internal/netctl/nft/guard_test.go server/internal/netctl/nft/detect_test.go
git commit -m "feat: add SSH lockout guard and host detection parsers"
```

---

### Task 3: nft executor (yoxla, tətbiq et, snapshot al)

**Files:**
- Create: `server/internal/netctl/nft/executor.go`
- Test: `server/internal/netctl/nft/executor_test.go`

**Interfaces:**
- Consumes: Task 1 (`Compile`, `TableName`, `fullRuleset`, `testNow`)
- Produces:
  - `type Runner interface{ Run(stdin string, name string, args ...string) (string, error) }`;
  - `type HostRunner struct{}` (əmri birbaşa icra edir; binary yoxdursa `nsenter -t 1 -m -u -i -n`);
  - `type Executor struct{ Runner Runner }`, metodları: `Check(script) error`, `Apply(script) error`, `Snapshot() (string, error)`;
  - paket daxili sabit `removeTable`.

- [ ] **Step 1: Uğursuz testi yaz** (`executor_test.go`)

```go
package nft

import (
	"os"
	"strings"
	"testing"
)

// TestExecutorRoundTripInKernel applies a ruleset, snapshots it, replaces it
// and restores the snapshot through the real nft binary. NFT_CHECK=1 only.
func TestExecutorRoundTripInKernel(t *testing.T) {
	if os.Getenv("NFT_CHECK") != "1" {
		t.Skip("set NFT_CHECK=1 to run against the kernel")
	}
	e := Executor{Runner: HostRunner{}}

	first, err := Compile(fullRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(first); err != nil {
		t.Fatal(err)
	}
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	second := fullRuleset()
	second.Blocked = nil
	second.Services = nil
	secondScript, err := Compile(second, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(secondScript); err != nil {
		t.Fatal(err)
	}
	if err := e.Check(snap); err != nil {
		t.Fatalf("snapshot must be a valid script: %v", err)
	}
	if err := e.Apply(snap); err != nil {
		t.Fatal(err)
	}
	listed, err := HostRunner{}.Run("", "nft", "list", "set", "inet", TableName, "blocked_v4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed, "198.51.100.0/24") {
		t.Fatalf("restore lost blocked entries:\n%s", listed)
	}

	// Removing the table through the empty-host snapshot.
	if err := e.Apply(removeTable); err != nil {
		t.Fatal(err)
	}
	if s, err := e.Snapshot(); err != nil || s != removeTable {
		t.Fatalf("missing table must snapshot as removal, got %q, %v", s, err)
	}
}
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

Fokuslu əmri `-run TestExecutorRoundTripInKernel` ilə işlət. Expected: build FAIL — `undefined: Executor`.

- [ ] **Step 3: `executor.go`-nu yaz**

```go
package nft

import (
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs a command on the host, feeding stdin, and returns its combined output.
type Runner interface {
	Run(stdin string, name string, args ...string) (string, error)
}

// HostRunner runs commands directly (the control plane shares the host's
// network namespace) and falls back to nsenter into PID 1's namespaces.
type HostRunner struct{}

// Run implements Runner.
func (HostRunner) Run(stdin string, name string, args ...string) (string, error) {
	out, err := run(stdin, name, args...)
	if err == nil {
		return out, nil
	}
	if _, lookErr := exec.LookPath(name); lookErr == nil {
		return out, err
	}
	nsArgs := append([]string{"-t", "1", "-m", "-u", "-i", "-n", "--", name}, args...)
	return run(stdin, "nsenter", nsArgs...)
}

func run(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// removeTable is the script that leaves the host without our table; it is
// the snapshot when the table does not exist yet.
const removeTable = "table inet " + TableName + "\ndelete table inet " + TableName + "\n"

// Executor validates, applies and snapshots table inet novusgate.
type Executor struct {
	Runner Runner
}

// Check validates a script against the kernel without changing anything.
func (e Executor) Check(script string) error {
	if out, err := e.Runner.Run(script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft check failed: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Apply loads a script atomically.
func (e Executor) Apply(script string) error {
	if out, err := e.Runner.Run(script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft apply failed: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Snapshot returns a script that restores the current table exactly,
// including dynamic set elements such as timed bans.
func (e Executor) Snapshot() (string, error) {
	out, err := e.Runner.Run("", "nft", "list", "table", "inet", TableName)
	if err != nil {
		if strings.Contains(out, "No such file or directory") {
			return removeTable, nil
		}
		return "", fmt.Errorf("nft list failed: %v: %s", err, strings.TrimSpace(out))
	}
	return removeTable + out, nil
}
```

- [ ] **Step 4: Kernel-də işlət**

Tam yoxlama əmrini işlət. Expected: `TestExecutorRoundTripInKernel` PASS: tətbiq, snapshot, əvəzetmə, bərpa və boş host snapshot-u. Fokuslu əmrdə (kernel olmadan) bu test SKIP olur.

- [ ] **Step 5: Commit**

```bash
git add server/internal/netctl/nft/executor.go server/internal/netctl/nft/executor_test.go
git commit -m "feat: add nft executor with check, apply and snapshot"
```

---

### Task 4: Təhlükəsiz tətbiq: təsdiq və ya avtomatik geri qayıtma

**Files:**
- Create: `server/internal/netctl/nft/safeapply.go`
- Test: `server/internal/netctl/nft/safeapply_test.go`

**Interfaces:**
- Consumes: Task 3 (`Executor`, `Runner`, `removeTable`), Task 1 (`testNow`)
- Produces:
  - `ErrPendingConfirmation`, `ErrNoPending`;
  - `type HostTimer interface{ Arm(rollbackScript string, after time.Duration) error; Disarm() error }`;
  - `type Pending struct{ ID string; Deadline time.Time }`;
  - `type SafeApplier struct{ Exec Executor; Timer HostTimer; Timeout time.Duration; Now func() time.Time; AfterFunc func(time.Duration, func()) func() bool }`;
  - `func NewSafeApplier(exec Executor, timer HostTimer, timeout time.Duration) *SafeApplier`;
  - `(*SafeApplier).Apply(script string, confirm bool) (Pending, error)`, `Confirm(id string) error`, `PendingChange() (Pending, bool)`;
  - `type SystemdTimer struct{ Runner Runner; Unit, Path string; WriteFile func(path, content string) error }`.

- [ ] **Step 1: Uğursuz testi yaz** (`safeapply_test.go`)

```go
package nft

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeRunner records commands and answers "nft list" with the current table.
type fakeRunner struct {
	calls    []string
	applied  []string // scripts passed to `nft -f -`
	table    string   // what `nft list table` returns; "" means no table
	failNext map[string]error
}

func (f *fakeRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if err, ok := f.failNext[cmd]; ok {
		delete(f.failNext, cmd)
		return "boom", err
	}
	switch cmd {
	case "nft list table inet novusgate":
		if f.table == "" {
			return "Error: No such file or directory", errors.New("exit status 1")
		}
		return f.table, nil
	case "nft -f -":
		f.applied = append(f.applied, stdin)
	}
	return "", nil
}

type fakeTimer struct {
	armed    bool
	script   string
	failArm  error
	disarmed int
}

func (t *fakeTimer) Arm(script string, after time.Duration) error {
	if t.failArm != nil {
		return t.failArm
	}
	t.armed, t.script = true, script
	return nil
}

func (t *fakeTimer) Disarm() error { t.armed = false; t.disarmed++; return nil }

func newTestApplier(r *fakeRunner, tm *fakeTimer) (*SafeApplier, *func()) {
	var fire func()
	s := &SafeApplier{
		Exec:    Executor{Runner: r},
		Timer:   tm,
		Timeout: 60 * time.Second,
		Now:     func() time.Time { return testNow },
		AfterFunc: func(d time.Duration, f func()) func() bool {
			fire = f
			return func() bool { fire = nil; return true }
		},
	}
	return s, &fire
}

func TestSafeApplyRollsBackWithoutConfirmation(t *testing.T) {
	r := &fakeRunner{table: "table inet novusgate {\n}\n"}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", true)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || !p.Deadline.Equal(testNow.Add(60*time.Second)) {
		t.Fatalf("unexpected pending %+v", p)
	}
	if !tm.armed || !strings.HasPrefix(tm.script, removeTable) {
		t.Fatal("host timer must be armed with the snapshot before applying")
	}
	if _, err := s.Apply("OTHER", true); !errors.Is(err, ErrPendingConfirmation) {
		t.Fatalf("second apply must wait, got %v", err)
	}

	(*fire)() // timeout without confirmation

	if got := r.applied[len(r.applied)-1]; got != removeTable+"table inet novusgate {\n}\n" {
		t.Fatalf("rollback applied %q", got)
	}
	if tm.armed {
		t.Fatal("host timer must be disarmed after the in-process rollback")
	}
	if _, ok := s.PendingChange(); ok {
		t.Fatal("no change may stay pending after rollback")
	}
}

func TestSafeApplyConfirmKeepsChange(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", true)
	if err != nil {
		t.Fatal(err)
	}
	if tm.script != removeTable {
		t.Fatalf("snapshot of a missing table must remove it, got %q", tm.script)
	}
	if err := s.Confirm("wrong-id"); !errors.Is(err, ErrNoPending) {
		t.Fatalf("wrong id must be rejected, got %v", err)
	}
	if err := s.Confirm(p.ID); err != nil {
		t.Fatal(err)
	}
	if *fire != nil || tm.armed {
		t.Fatal("confirm must stop both timers")
	}
	if len(r.applied) != 1 || r.applied[0] != "NEW" {
		t.Fatalf("only the new ruleset may be applied, got %v", r.applied)
	}
}

func TestSafeApplyRefusesWithoutSafetyNet(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{failArm: errors.New("systemd-run missing")}
	s, _ := newTestApplier(r, tm)

	if _, err := s.Apply("NEW", true); err == nil {
		t.Fatal("apply must fail when the rollback timer cannot be armed")
	}
	if len(r.applied) != 0 {
		t.Fatal("nothing may be applied without the safety net")
	}
}

func TestSafeApplyCheckFailureChangesNothing(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{"nft -c -f -": errors.New("exit status 1")}}
	tm := &fakeTimer{}
	s, _ := newTestApplier(r, tm)

	if _, err := s.Apply("BROKEN", true); err == nil {
		t.Fatal("a ruleset rejected by nft -c must not be applied")
	}
	if len(r.applied) != 0 || tm.armed {
		t.Fatal("check failure must leave the host untouched")
	}
}

func TestSafeApplyFailedApplyDisarms(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{"nft -f -": errors.New("exit status 1")}}
	tm := &fakeTimer{}
	s, _ := newTestApplier(r, tm)

	if _, err := s.Apply("NEW", true); err == nil {
		t.Fatal("expected apply error")
	}
	if tm.armed || tm.disarmed != 1 {
		t.Fatal("a failed apply must disarm the host timer")
	}
	if _, ok := s.PendingChange(); ok {
		t.Fatal("a failed apply must not leave a pending change")
	}
}

func TestSafeApplyWithoutConfirmIsImmediate(t *testing.T) {
	r := &fakeRunner{}
	tm := &fakeTimer{}
	s, fire := newTestApplier(r, tm)

	p, err := s.Apply("NEW", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "" || *fire != nil || tm.armed {
		t.Fatal("unconfirmed mode must not arm timers")
	}
}

func TestSystemdTimerCommands(t *testing.T) {
	r := &fakeRunner{failNext: map[string]error{
		"systemctl stop novusgate-fw-rollback.timer": errors.New("exit status 5"),
	}}
	written := map[string]string{}
	tm := SystemdTimer{Runner: r, Unit: "novusgate-fw-rollback", Path: "/var/lib/novusgate/fw-rollback.nft",
		WriteFile: func(p, c string) error { written[p] = c; return nil }}

	// "boom" output is not "not loaded", so the stop failure is a real error.
	if err := tm.Arm("SNAP", 60*time.Second); err == nil {
		t.Fatal("a failing stop must abort Arm")
	}
	r.calls = nil
	if err := tm.Arm("SNAP", 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if written["/var/lib/novusgate/fw-rollback.nft"] != "SNAP" {
		t.Fatal("rollback script must be written before arming")
	}
	want := "systemd-run --unit=novusgate-fw-rollback --on-active=60s --timer-property=AccuracySec=1s nft -f /var/lib/novusgate/fw-rollback.nft"
	if r.calls[len(r.calls)-1] != want {
		t.Fatalf("got %q\nwant %q", r.calls[len(r.calls)-1], want)
	}
}
```

- [ ] **Step 2: Testi işlət və uğursuz olduğunu gör**

Fokuslu əmri `-run 'TestSafeApply|TestSystemdTimer'` ilə işlət. Expected: build FAIL — `undefined: SafeApplier`.

- [ ] **Step 3: `safeapply.go`-nu yaz**

```go
package nft

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	// ErrPendingConfirmation means an earlier change still waits for confirmation.
	ErrPendingConfirmation = errors.New("a firewall change is waiting for confirmation")
	// ErrNoPending means there is no change with that id to confirm.
	ErrNoPending = errors.New("no pending firewall change with this id")
)

// HostTimer restores a snapshot from outside the control plane, so a change
// that cuts off the operator is rolled back even if the process dies.
type HostTimer interface {
	Arm(rollbackScript string, after time.Duration) error
	Disarm() error
}

// Pending describes a change that is live but not yet confirmed.
type Pending struct {
	ID       string
	Deadline time.Time
}

// SafeApplier applies rulesets with an automatic rollback unless confirmed.
type SafeApplier struct {
	Exec      Executor
	Timer     HostTimer
	Timeout   time.Duration
	Now       func() time.Time
	AfterFunc func(d time.Duration, f func()) (stop func() bool)

	mu      sync.Mutex
	pending *pendingChange
}

type pendingChange struct {
	id       string
	snapshot string
	deadline time.Time
	stop     func() bool
}

// NewSafeApplier wires the real clock and timers.
func NewSafeApplier(exec Executor, timer HostTimer, timeout time.Duration) *SafeApplier {
	return &SafeApplier{
		Exec:    exec,
		Timer:   timer,
		Timeout: timeout,
		Now:     time.Now,
		AfterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
	}
}

// Apply validates and loads script. With confirm=false the change is final
// immediately (used by callers that cannot confirm, e.g. legacy endpoints);
// otherwise it stays pending and is rolled back after Timeout unless Confirm
// is called with the returned id.
func (s *SafeApplier) Apply(script string, confirm bool) (Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return Pending{}, ErrPendingConfirmation
	}
	if err := s.Exec.Check(script); err != nil {
		return Pending{}, err
	}
	if !confirm {
		return Pending{}, s.Exec.Apply(script)
	}
	snapshot, err := s.Exec.Snapshot()
	if err != nil {
		return Pending{}, err
	}
	// Never apply without the host-side safety net in place.
	if err := s.Timer.Arm(snapshot, s.Timeout); err != nil {
		return Pending{}, fmt.Errorf("arm rollback timer: %w", err)
	}
	if err := s.Exec.Apply(script); err != nil {
		if derr := s.Timer.Disarm(); derr != nil {
			log.Printf("firewall: disarm after failed apply: %v", derr)
		}
		return Pending{}, err
	}
	id := newID()
	p := &pendingChange{id: id, snapshot: snapshot, deadline: s.Now().Add(s.Timeout)}
	p.stop = s.AfterFunc(s.Timeout, func() { s.rollback(id) })
	s.pending = p
	return Pending{ID: id, Deadline: p.deadline}, nil
}

// Confirm makes the pending change permanent.
func (s *SafeApplier) Confirm(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.id != id {
		return ErrNoPending
	}
	s.pending.stop()
	s.pending = nil
	return s.Timer.Disarm()
}

// PendingChange reports the change waiting for confirmation, if any.
func (s *SafeApplier) PendingChange() (Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return Pending{}, false
	}
	return Pending{ID: s.pending.id, Deadline: s.pending.deadline}, true
}

func (s *SafeApplier) rollback(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.id != id {
		return
	}
	if err := s.Exec.Apply(s.pending.snapshot); err != nil {
		// The host timer is still armed and will retry the restore.
		log.Printf("firewall: rollback failed, host timer will restore: %v", err)
		s.pending = nil
		return
	}
	s.pending = nil
	if err := s.Timer.Disarm(); err != nil {
		log.Printf("firewall: disarm after rollback: %v", err)
	}
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// SystemdTimer arms a transient systemd timer on the host that loads the
// rollback script with nft after the timeout.
type SystemdTimer struct {
	Runner    Runner
	Unit      string // e.g. "novusgate-fw-rollback"
	Path      string // host path for the rollback script
	WriteFile func(path, content string) error
}

// Arm implements HostTimer.
func (t SystemdTimer) Arm(rollbackScript string, after time.Duration) error {
	if err := t.Disarm(); err != nil {
		return err
	}
	if err := t.WriteFile(t.Path, rollbackScript); err != nil {
		return err
	}
	secs := int(after / time.Second)
	if secs < 1 {
		secs = 1
	}
	out, err := t.Runner.Run("", "systemd-run",
		"--unit="+t.Unit,
		fmt.Sprintf("--on-active=%ds", secs),
		"--timer-property=AccuracySec=1s",
		"nft", "-f", t.Path)
	if err != nil {
		return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Disarm implements HostTimer. A timer that is not loaded is already disarmed.
func (t SystemdTimer) Disarm() error {
	out, err := t.Runner.Run("", "systemctl", "stop", t.Unit+".timer")
	if err != nil && !strings.Contains(out, "not loaded") {
		return fmt.Errorf("systemctl stop: %v: %s", err, strings.TrimSpace(out))
	}
	// Clear a failed transient unit so the next systemd-run can reuse the name;
	// "not loaded" just means there is nothing to clear.
	if out, err := t.Runner.Run("", "systemctl", "reset-failed", t.Unit+".service"); err != nil && !strings.Contains(out, "not loaded") {
		log.Printf("firewall: reset-failed %s: %v: %s", t.Unit, err, strings.TrimSpace(out))
	}
	return nil
}
```

- [ ] **Step 4: Testləri işlət**

Step 2-dəki əmri işlət. Expected: `PASS` (7 test).

- [ ] **Step 5: Commit**

```bash
git add server/internal/netctl/nft/safeapply.go server/internal/netctl/nft/safeapply_test.go
git commit -m "feat: add confirm-or-rollback firewall applier with systemd timer"
```

---

### Task 5: DB modelləri → mühərrik modeli və host aşkarlanması

**Files:**
- Create: `server/internal/controlplane/firewall/build.go`
- Create: `server/internal/controlplane/firewall/preview.go`
- Test: `server/internal/controlplane/firewall/build_test.go`
- Test: `server/internal/controlplane/firewall/preview_test.go`

**Interfaces:**
- Consumes:
  - Task 1 (`nft.Ruleset`, `nft.VPNRule`, `nft.VPNNetwork`, `nft.PortRange`, `nft.Compile`);
  - Task 2 (`nft.ParseSSHDPorts`, `nft.ParseRouteDevice`);
  - Task 3 (`nft.Runner`);
  - mövcud modellər: `models.Network` (`ID`, `Name`, `CIDR`, `InterfaceName`, `ListenPort int`), `models.VPNFirewallRule` (`SourceType`/`DestType` = `any|network|node|custom`, `*NetworkID`, `*NodeID`, `SourceIP`/`DestIP`, `Protocol`, `Port`, `Action`, `Enabled`), `models.Node` (`VirtualIP net.IP`);
  - `store.Store`-un `ListNetworks`, `ListVPNFirewallRules` (`priority ASC` sıralanır) və `GetNode` metodları.
- Produces:
  - `func NetworksFromModels([]*models.Network) ([]nft.VPNNetwork, []error)`;
  - `func VPNRulesFromModels(rules, networks map[string]*models.Network, nodes map[string]*models.Node) ([]nft.VPNRule, []error)`;
  - `func ParsePorts(string) ([]nft.PortRange, error)`;
  - `type Source interface{ ListNetworks; ListVPNFirewallRules; GetNode }`;
  - `func DetectHost(nft.Runner) ([]uint16, string, error)`;
  - `func BuildRuleset(ctx, Source, sshPorts []uint16, egress string) (nft.Ruleset, []error, error)`.

- [ ] **Step 1: Uğursuz testləri yaz**

`build_test.go`:
```go
package firewall

import (
	"net"
	"testing"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func strPtr(s string) *string { return &s }

func TestVPNRulesFromModels(t *testing.T) {
	networks := map[string]*models.Network{
		"net-a": {ID: "net-a", Name: "A", CIDR: "10.20.0.0/24", InterfaceName: "wg1"},
		"net-b": {ID: "net-b", Name: "B", CIDR: "10.30.0.0/24", InterfaceName: "wg2"},
	}
	nodes := map[string]*models.Node{
		"node-1": {ID: "node-1", VirtualIP: net.ParseIP("10.30.0.5")},
	}
	rules := []*models.VPNFirewallRule{
		{ID: "r1", Name: "a-to-b-ssh", SourceType: "network", SourceNetworkID: strPtr("net-a"),
			DestType: "node", DestNodeID: strPtr("node-1"), Protocol: "tcp", Port: "22, 8000:8100", Action: "accept", Enabled: true},
		{ID: "r2", Name: "disabled", SourceType: "any", DestType: "any", Protocol: "all", Action: "drop", Enabled: false},
		{ID: "r3", Name: "custom-host", SourceType: "custom", SourceIP: "10.20.0.9", DestType: "network",
			DestNetworkID: strPtr("net-b"), Protocol: "icmp", Action: "accept", Enabled: true},
		{ID: "r4", Name: "dangling", SourceType: "network", SourceNetworkID: strPtr("gone"), DestType: "any",
			Protocol: "all", Action: "accept", Enabled: true},
		{ID: "r5", Name: "bad-port", SourceType: "any", DestType: "any", Protocol: "udp", Port: "53-x", Action: "accept", Enabled: true},
	}

	got, errs := VPNRulesFromModels(rules, networks, nodes)

	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(got), got)
	}
	r1 := got[0]
	if r1.ID != "r1" || r1.Src.String() != "10.20.0.0/24" || r1.Dst.String() != "10.30.0.5/32" ||
		r1.Proto != nft.TCP || len(r1.Ports) != 2 || r1.Ports[1] != (nft.PortRange{From: 8000, To: 8100}) {
		t.Fatalf("unexpected r1: %+v", r1)
	}
	if got[1].Src.String() != "10.20.0.9/32" || got[1].Proto != nft.ICMP {
		t.Fatalf("unexpected r3: %+v", got[1])
	}
	if len(errs) != 2 {
		t.Fatalf("want 2 conversion errors (dangling network, bad port), got %v", errs)
	}
}

func TestNetworksFromModels(t *testing.T) {
	got, errs := NetworksFromModels([]*models.Network{
		{Name: "Admin", CIDR: "10.99.0.1/24", InterfaceName: "wg0", ListenPort: 51820},
		{Name: "Legacy", CIDR: "10.40.0.0/24"},
	})
	if len(got) != 1 || got[0].CIDR.String() != "10.99.0.0/24" || got[0].ListenPort != 51820 {
		t.Fatalf("unexpected networks %+v", got)
	}
	if len(errs) != 1 {
		t.Fatalf("network without interface must be reported, got %v", errs)
	}
}

func TestParsePorts(t *testing.T) {
	for _, bad := range []string{"", "0", "70000", "9000-8000", "a", "80,"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) must fail", bad)
		}
	}
	got, err := ParsePorts("80,443,8000-8100")
	if err != nil || len(got) != 3 || got[2] != (nft.PortRange{From: 8000, To: 8100}) {
		t.Fatalf("ParsePorts = %v, %v", got, err)
	}
}
```

`preview_test.go`:
```go
package firewall

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type fakeSource struct {
	networks []*models.Network
	rules    []*models.VPNFirewallRule
	nodes    map[string]*models.Node
	getCalls int
}

func (f *fakeSource) ListNetworks(context.Context) ([]*models.Network, error) { return f.networks, nil }
func (f *fakeSource) ListVPNFirewallRules(context.Context) ([]*models.VPNFirewallRule, error) {
	return f.rules, nil
}
func (f *fakeSource) GetNode(_ context.Context, id string) (*models.Node, error) {
	f.getCalls++
	return f.nodes[id], nil
}

func TestBuildRulesetCompiles(t *testing.T) {
	src := &fakeSource{
		networks: []*models.Network{
			{ID: "n0", Name: "Admin", CIDR: "10.99.0.0/24", InterfaceName: "wg0", ListenPort: 51820},
			{ID: "n1", Name: "Office", CIDR: "10.20.0.0/24", InterfaceName: "wg1", ListenPort: 51821},
		},
		rules: []*models.VPNFirewallRule{
			{ID: "r1", Name: "office-to-printer", SourceType: "network", SourceNetworkID: strPtr("n1"),
				DestType: "node", DestNodeID: strPtr("p1"), Protocol: "tcp", Port: "9100", Action: "accept", Enabled: true},
			{ID: "r2", Name: "same-node-again", SourceType: "node", SourceNodeID: strPtr("p1"),
				DestType: "any", Protocol: "all", Action: "drop", Enabled: true},
		},
		nodes: map[string]*models.Node{"p1": {ID: "p1", VirtualIP: net.ParseIP("10.99.0.50")}},
	}

	rs, warnings, err := BuildRuleset(context.Background(), src, []uint16{22}, "eth0")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("BuildRuleset: %v, warnings %v", err, warnings)
	}
	if src.getCalls != 1 {
		t.Fatalf("each referenced node must be loaded once, got %d calls", src.getCalls)
	}
	script, err := nft.Compile(rs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `ip saddr 10.20.0.0/24 ip daddr 10.99.0.50/32 tcp dport { 9100 } counter accept comment "rule:r1"`) {
		t.Fatalf("missing converted rule:\n%s", script)
	}
}

type fakeHost struct{ out map[string]string }

func (f fakeHost) Run(_ string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if out, ok := f.out[cmd]; ok {
		return out, nil
	}
	return "not found", errors.New("exit status 127")
}

func TestDetectHost(t *testing.T) {
	ports, egress, err := DetectHost(fakeHost{out: map[string]string{
		"sshd -T":              "port 2222\nport 22\npermitrootlogin yes\n",
		"ip route get 8.8.8.8": "8.8.8.8 via 192.0.2.1 dev ens3 src 192.0.2.10 uid 0\n",
	}})
	if err != nil || len(ports) != 2 || egress != "ens3" {
		t.Fatalf("DetectHost = %v, %q, %v", ports, egress, err)
	}
	if _, _, err := DetectHost(fakeHost{out: map[string]string{}}); err == nil {
		t.Fatal("missing sshd must be an error, never a guessed port")
	}
}
```

- [ ] **Step 2: Testləri işlət və uğursuz olduğunu gör**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go test ./internal/controlplane/firewall/ -v
```
Expected: build FAIL — `undefined: VPNRulesFromModels`, `undefined: BuildRuleset`.

- [ ] **Step 3: `build.go`-nu yaz**

```go
// Package firewall turns stored NovusGate state into the nft engine model.
package firewall

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// NetworksFromModels converts stored networks; networks without an interface
// (never brought up) are skipped and reported.
func NetworksFromModels(networks []*models.Network) ([]nft.VPNNetwork, []error) {
	var out []nft.VPNNetwork
	var errs []error
	for _, n := range networks {
		if n.InterfaceName == "" {
			errs = append(errs, fmt.Errorf("network %s has no interface", n.Name))
			continue
		}
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			errs = append(errs, fmt.Errorf("network %s: %v", n.Name, err))
			continue
		}
		port := n.ListenPort
		if port < 0 || port > 65535 {
			port = 0
		}
		out = append(out, nft.VPNNetwork{Interface: n.InterfaceName, CIDR: prefix.Masked(), ListenPort: uint16(port)})
	}
	return out, errs
}

// VPNRulesFromModels converts stored VPN rules in their stored order.
// Disabled rules are skipped; a rule that cannot be converted is reported
// and skipped so one bad rule never blocks the rest.
func VPNRulesFromModels(rules []*models.VPNFirewallRule, networks map[string]*models.Network, nodes map[string]*models.Node) ([]nft.VPNRule, []error) {
	var out []nft.VPNRule
	var errs []error
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		src, err := endpoint(r.SourceType, r.SourceNetworkID, r.SourceNodeID, r.SourceIP, networks, nodes)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s source: %v", r.Name, err))
			continue
		}
		dst, err := endpoint(r.DestType, r.DestNetworkID, r.DestNodeID, r.DestIP, networks, nodes)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s destination: %v", r.Name, err))
			continue
		}
		proto := nft.Protocol(r.Protocol)
		if proto == "" {
			proto = nft.All
		}
		var ports []nft.PortRange
		if r.Port != "" && (proto == nft.TCP || proto == nft.UDP) {
			if ports, err = ParsePorts(r.Port); err != nil {
				errs = append(errs, fmt.Errorf("rule %s: %v", r.Name, err))
				continue
			}
		}
		out = append(out, nft.VPNRule{ID: r.ID, Src: src, Dst: dst, Proto: proto, Ports: ports, Action: r.Action})
	}
	return out, errs
}

func endpoint(kind string, networkID, nodeID *string, custom string, networks map[string]*models.Network, nodes map[string]*models.Node) (netip.Prefix, error) {
	switch kind {
	case "any":
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	case "network":
		if networkID == nil || networks[*networkID] == nil {
			return netip.Prefix{}, fmt.Errorf("network not found")
		}
		p, err := netip.ParsePrefix(networks[*networkID].CIDR)
		return p.Masked(), err
	case "node":
		if nodeID == nil || nodes[*nodeID] == nil {
			return netip.Prefix{}, fmt.Errorf("node not found")
		}
		addr, ok := netip.AddrFromSlice(nodes[*nodeID].VirtualIP)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("node has no address")
		}
		return netip.PrefixFrom(addr.Unmap(), 32), nil
	case "custom":
		if strings.Contains(custom, "/") {
			p, err := netip.ParsePrefix(custom)
			return p.Masked(), err
		}
		addr, err := netip.ParseAddr(custom)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("unknown endpoint type %q", kind)
}

// ParsePorts accepts "22", "80,443" and ranges written "8000-9000" or "8000:9000".
func ParsePorts(s string) ([]nft.PortRange, error) {
	var out []nft.PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		sep := strings.IndexAny(part, "-:")
		fromS, toS := part, part
		if sep > 0 {
			fromS, toS = part[:sep], part[sep+1:]
		}
		from, err1 := strconv.Atoi(fromS)
		to, err2 := strconv.Atoi(toS)
		if err1 != nil || err2 != nil || from < 1 || to > 65535 || to < from {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		out = append(out, nft.PortRange{From: uint16(from), To: uint16(to)})
	}
	return out, nil
}
```

- [ ] **Step 4: `preview.go`-nu yaz**

```go
package firewall

import (
	"context"
	"fmt"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Source is the part of the store the firewall builder reads.
type Source interface {
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	ListVPNFirewallRules(ctx context.Context) ([]*models.VPNFirewallRule, error)
	GetNode(ctx context.Context, id string) (*models.Node, error)
}

// DetectHost reads the host facts a ruleset depends on: the ports sshd
// listens on and the interface that carries the default route.
func DetectHost(r nft.Runner) ([]uint16, string, error) {
	out, err := r.Run("", "sshd", "-T")
	if err != nil {
		return nil, "", fmt.Errorf("sshd -T: %v: %s", err, out)
	}
	ports := nft.ParseSSHDPorts(out)
	if len(ports) == 0 {
		return nil, "", fmt.Errorf("sshd -T reported no port")
	}
	route, err := r.Run("", "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return nil, "", fmt.Errorf("ip route get: %v: %s", err, route)
	}
	egress, err := nft.ParseRouteDevice(route)
	if err != nil {
		return nil, "", err
	}
	return ports, egress, nil
}

// BuildRuleset assembles the engine model from stored state. Services,
// blocked addresses, forwards and egress nodes are not stored yet (P3b), so
// they are empty here. Conversion problems are returned as warnings.
func BuildRuleset(ctx context.Context, src Source, sshPorts []uint16, egress string) (nft.Ruleset, []error, error) {
	networks, err := src.ListNetworks(ctx)
	if err != nil {
		return nft.Ruleset{}, nil, fmt.Errorf("list networks: %w", err)
	}
	rules, err := src.ListVPNFirewallRules(ctx)
	if err != nil {
		return nft.Ruleset{}, nil, fmt.Errorf("list VPN rules: %w", err)
	}
	byID := map[string]*models.Network{}
	for _, n := range networks {
		byID[n.ID] = n
	}
	nodes := map[string]*models.Node{}
	for _, r := range rules {
		for _, id := range []*string{r.SourceNodeID, r.DestNodeID} {
			if id == nil || nodes[*id] != nil {
				continue
			}
			node, err := src.GetNode(ctx, *id)
			if err != nil {
				return nft.Ruleset{}, nil, fmt.Errorf("get node %s: %w", *id, err)
			}
			if node != nil {
				nodes[*id] = node
			}
		}
	}
	vpnNetworks, warnings := NetworksFromModels(networks)
	vpnRules, ruleWarnings := VPNRulesFromModels(rules, byID, nodes)
	warnings = append(warnings, ruleWarnings...)
	return nft.Ruleset{
		SSHPorts:        sshPorts,
		EgressInterface: egress,
		Networks:        vpnNetworks,
		VPNRules:        vpnRules,
	}, warnings, nil
}
```

- [ ] **Step 5: Testləri işlət**

Step 2-dəki əmri işlət. Expected: `PASS` (5 test).

- [ ] **Step 6: Commit**

```bash
git add server/internal/controlplane/firewall/
git commit -m "feat: build nftables ruleset from stored networks and VPN rules"
```

---

### Task 6: `firewall preview` əmri, image-də nftables, sənədlər

**Files:**
- Create: `server/cmd/control-plane/firewall_cmd.go`
- Modify: `server/deployments/docker/Dockerfile.control-plane` (runtime `apk add` sətri)
- Create: `docs/architecture.md`
- Modify: `docs/active-context.md`

**Interfaces:**
- Consumes: Task 3–5 (`nft.HostRunner`, `nft.Executor`, `nft.Compile`, `firewall.DetectHost`, `firewall.BuildRuleset`); mövcud `rootCmd` və `store.New` (`cmd/control-plane/main.go`)
- Produces: `novusgate-server firewall preview [--database URL] [--check]`. Skripti stdout-a, xəbərdarlıqları stderr-ə yazır. `--check` yalnız `nft -c` icra edir.

- [ ] **Step 1: Əmri yaz** (`firewall_cmd.go`)

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/spf13/cobra"
)

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Inspect the nftables firewall engine",
}

var firewallPreviewCmd = &cobra.Command{
	Use:   "preview",
	Short: "Print the nftables ruleset compiled from the database (changes nothing)",
	RunE:  runFirewallPreview,
}

func init() {
	firewallPreviewCmd.Flags().String("database", "", "Database connection string")
	firewallPreviewCmd.Flags().Bool("check", false, "Also validate the ruleset with nft -c (needs nft and CAP_NET_ADMIN)")
	firewallCmd.AddCommand(firewallPreviewCmd)
	rootCmd.AddCommand(firewallCmd)
}

func runFirewallPreview(cmd *cobra.Command, args []string) error {
	databaseURL, _ := cmd.Flags().GetString("database")
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return fmt.Errorf("database connection string is required (--database or DATABASE_URL)")
	}
	db, err := store.New(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	runner := nft.HostRunner{}
	sshPorts, egress, err := firewall.DetectHost(runner)
	if err != nil {
		return fmt.Errorf("host detection failed: %w", err)
	}
	rs, warnings, err := firewall.BuildRuleset(context.Background(), db, sshPorts, egress)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	script, err := nft.Compile(rs, time.Now())
	if err != nil {
		return err
	}
	fmt.Print(script)

	if check, _ := cmd.Flags().GetBool("check"); check {
		if err := (nft.Executor{Runner: runner}).Check(script); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "nft -c: OK")
	}
	return nil
}
```

- [ ] **Step 2: Image-ə nftables əlavə et**

`server/deployments/docker/Dockerfile.control-plane`-də runtime mərhələsinin bu sətrini:
```dockerfile
RUN apk add --no-cache ca-certificates curl wireguard-tools iptables util-linux
```
bununla əvəz et:
```dockerfile
RUN apk add --no-cache ca-certificates curl wireguard-tools iptables nftables util-linux
```

- [ ] **Step 3: Əmrin qeydiyyatını və tam yoxlamanı icra et**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go run ./cmd/control-plane firewall preview --help
```
Expected: `Print the nftables ruleset compiled from the database (changes nothing)` və `--check`, `--database` bayraqları.

Sonra Global Constraints-dəki tam yoxlama əmrini işlət. Expected: `ok` `…/api/rest`, `…/controlplane/firewall` və `…/netctl/nft` üçün; exit 0.

Image-i yığ və nft-nin image-də olduğunu yoxla:
```bash
cd /c/Users/Administrator/Desktop/NovusGate/server
docker build -f deployments/docker/Dockerfile.control-plane -t novusgate-cp:p3a .
MSYS_NO_PATHCONV=1 docker run --rm --entrypoint nft novusgate-cp:p3a --version
MSYS_NO_PATHCONV=1 docker run --rm novusgate-cp:p3a firewall preview --help
```
Expected: `nftables v1.0.9` və help mətni.

- [ ] **Step 4: Sənədləşdir**

`docs/architecture.md` yarat:
```markdown
# Arxitektura

## Firewall mühərriki (P3a)
- `server/internal/netctl/nft` — NovusGate-in öz nftables cədvəli `table inet novusgate` (IPv4 + IPv6):
  - `Compile` modeli atomik `nft -f` skriptinə çevirir (`table` → `delete table` → yenidən təyin);
  - `Validate` nft sintaksisinə "inject"-in və təhlükəli portların qarşısını alır;
  - `CheckProtection` SSH lockout-a qarşı qoruyur (fail closed);
  - `Executor` nft CLI üzərindən `Check`, `Apply` və `Snapshot` edir;
  - `SafeApplier` snapshot + `systemd-run` host timer + prosesdaxili timer ilə "60 saniyəyə təsdiqlə, yoxsa geri qayıt" mexanizmini qurur.
- `server/internal/controlplane/firewall` — DB-dəki şəbəkələri və VPN qaydalarını mühərrik modelinə çevirir və host faktlarını (`sshd -T`, `ip route get`) aşkarlayır.
- `novusgate-server firewall preview [--check]` — DB-dən ruleset-i göstərir. Hostu **dəyişmir**: `--check` yalnız `nft -c` edir.
- Hazırda heç bir HTTP endpoint və ya startup kodu nft tətbiq etmir. Tətbiq P3b-də `FIREWALL_ENGINE` bayrağı ilə gələcək.
- Semantika: nftables-də `accept` yekun deyil, `drop` yekundur. Siyasət drop ilə tətbiq olunur, Docker-in və fail2ban-ın cədvəllərinə toxunulmur.
- Testlər: `server/scripts/test-in-docker.sh` (`NFT_CHECK=1` ilə kernel yoxlaması).
```

`docs/active-context.md`-də "Son Sessiya" bölməsini P3a ilə yenilə: tarix, tapşırıq (bu planın yolu), nəticə (Task 1–6 commit-ləri və tam yoxlamanın çıxışı), davam (P3b planı). "Son Dəyişikliklər" cədvəlinə P3a üçün bir sətir əlavə et. Fayl 400 sətri keçməməlidir.

- [ ] **Step 5: Commit**

```bash
git add server/cmd/control-plane/firewall_cmd.go server/deployments/docker/Dockerfile.control-plane docs/architecture.md docs/active-context.md
git commit -m "feat: add firewall preview command and nftables to control-plane image"
```
