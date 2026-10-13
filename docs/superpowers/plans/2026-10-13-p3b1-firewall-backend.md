# P3b-1 — Firewall Mühərrikinin Backend İnteqrasiyası: İmplementasiya Planı

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** P3a mühərrikini control plane-ə qoşmaq. Bu plan aşağıdakıları əlavə edir:
- DB cədvəlləri (servislər, IP qaydaları, forward-lar, egress);
- `FIREWALL_ENGINE=iptables|shadow|nft` rejimləri;
- dəyişikliyi təsdiqdən sonra DB-yə yazan `Engine`;
- `/api/v1/firewall/v2/*` API-si;
- nft rejimində köhnə panel endpoint-lərinin adapterləri (cavab formaları eyni qalır);
- iptables-dən bir dəfəlik idxal;
- ban bitəndə avtomatik reconcile.

**Default `iptables`-dir, yəni bu plan icra olunanda heç bir serverin davranışı dəyişmir.**

**Architecture:**
- `firewall.Engine` DB-dən vəziyyəti oxuyur, `Change.Mutate` ilə onu yaddaşda dəyişir, nft ilə tətbiq edir. Yalnız dəyişiklik canlı olandan sonra, yəni dərhal və ya təsdiqdən sonra, `Change.Commit` ilə DB-yə yazır. Rollback olan dəyişiklik heç vaxt saxlanmır.
- REST qatı v1 endpoint-lərində validasiyadan sonra `engineEnforces()` budağı ilə adapterə keçir.
- Host-dan asılı hər şey `nft.Runner` interfeysi arxasındadır.

**Tech Stack:** Go 1.23, PostgreSQL 16 (`lib/pq`, `pq.Array`), nftables, Docker (testlər üçün).

**Spec:** `docs/superpowers/specs/2026-10-13-p3-firewall-design.md` (§4, §5, §6 P3b, §6a)

## Global Constraints

- **Yeni Go paketi əlavə olunmur.** `github.com/lib/pq` və `github.com/google/uuid` artıq `go.mod`-dadır.
- **DB yalnız genişlənir.** Rollback faylı `migrations_rollback/` qovluğundadır. O qovluq embed olunmur, ona görə avtomatik icra edilmir.
- **`FIREWALL_ENGINE` boş olanda və ya `iptables` olanda** köhnə kod yolları dəyişmir. `engineEnforces()` yalnız `nft` rejimində true qaytarır.
- **nft rejimində v1 cavab formaları** v1 ilə eyni açarları saxlayır: `status`, `message`, `port`, `protocol`, `source`, `rules_deleted`, `ip`, `ports`, `chain`, `line_number`, `deleted_rule`, `permanent_bans`, `count`, `type`.
- **Köhnə fayllarda (`handlers.go`, `firewall_handlers.go`, `main.go`) yalnız göstərilən əlavələr edilir.** Bu fayllarda `gofmt -w` işlədilmir, çünki köhnə kodu yenidən formatlamaq scope-dan kənardır.
- Kod şərhləri ingiliscədir. Commit mesajlarında `Co-Authored-By`, `Claude`, `Anthropic` sözləri yazılmır.
- **Testlər Docker-də işlədilir:**
  - DB testləri daxil: `bash server/scripts/test-with-postgres.sh`
  - DB-siz: `MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 bash scripts/test-in-docker.sh`
  - Docker argumentlərində `$` və `|` olmamalıdır.
- **Privileged konteynerlə end-to-end sınaq aparılmır** (istifadəçi qərarı). Real kernel sınağı staging runbook-undadır (Task 5).

## Review Focus

1. **Bazada saxlanmış etibarsız sətir**, məsələn iptables-dən idxal olunmuş, rezerv 8443 portuna açıq servis. Bütün dəyişiklikləri bloklamamalıdır, yalnız xəbərdarlıq verməlidir. Eyni səhv yeni bir dəyişiklikdə isə 400 ilə rədd edilməlidir. Test: Task 3 `TestInvalidStoredRowWarnsButInvalidChangeIsRejected`.
2. **Rollback olan dəyişiklik DB-yə və boot faylına heç vaxt düşməməlidir.** Test: Task 3 `TestRolledBackChangeIsNeverStored`.
3. **Operatorun öz ünvanını (və ya WireGuard endpoint-ini) bloklamaq** v1 və v2 yollarının hamısında 400 qaytarmalıdır. Test: Task 4 `TestLegacyIPEndpointsAndPermanentBansInNftMode`.
4. **İdxal yarıda kəsilərsə**, təkrar cəhd qaydaları ikiqat yazmamalıdır. Test: Task 2 `TestImportFirewallRulesIsAtomic`, Task 3 `TestImportIptablesRunsOnce`.
5. **Store və REST testləri eyni test DB-ni paylaşır.** Paralel işləsələr bir-birinin cədvəllərini silərlər, ona görə `-p 1` istifadə olunur (Task 2).

---

### Task 1: nft modelinə per-source IP qaydaları (Allow IP və portla məhdud Block IP)

**Files:**
- Modify (tam əvəz): `server/internal/netctl/nft/model.go`, `validate.go`, `compile.go`, `guard.go`
- Create: `server/internal/netctl/nft/iprules_test.go`
- Modify: `.gitattributes`

**Interfaces:**
- Consumes: P3a `nft` paketi.
- Produces:
  - `type IPRule struct{ ID string; Prefix netip.Prefix; Action string /*block|allow*/; Proto Protocol; Ports []PortRange }`;
  - `Ruleset.IPRules []IPRule`;
  - `CheckProtection` portla məhdud blokları da yoxlayır və ünvanları `Unmap()` edir.

- [ ] **Step 1: `.gitattributes`-a Go faylları üçün LF qaydasını əlavə et**

```gitattributes
# gofmt checks in scripts/test-in-docker.sh fail on CRLF checkouts.
*.go text eol=lf
```

- [ ] **Step 2: Uğursuz testi yaz** (`iprules_test.go`)

```go
package nft

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func ipRulesRuleset() Ruleset {
	rs := fullRuleset()
	rs.IPRules = []IPRule{
		{ID: "no-web", Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: "block", Proto: TCP,
			Ports: []PortRange{{80, 80}, {443, 443}}},
		{ID: "office", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Action: "allow"},
		{ID: "monitor", Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Action: "allow", Proto: UDP,
			Ports: []PortRange{{161, 162}}},
	}
	return rs
}

func TestIPRulesRendering(t *testing.T) {
	got, err := Compile(ipRulesRuleset(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	block := `ip saddr 203.0.113.7 tcp dport { 80, 443 } counter drop comment "ip:no-web"`
	allowAll := `ip saddr 198.51.100.0/24 accept comment "ip:office"`
	allowV6 := `ip6 saddr 2001:db8:1::/48 udp dport { 161-162 } accept comment "ip:monitor"`
	for _, s := range []string{block, allowAll, allowV6} {
		if !strings.Contains(got, s) {
			t.Fatalf("missing %q\n%s", s, got)
		}
	}
	est := strings.Index(got, "ct state established,related accept")
	if strings.Index(got, block) > est {
		t.Fatal("port-scoped blocks must come before established, so they cut live connections")
	}
	if strings.Index(got, allowAll) < strings.Index(got, `comment "svc:https"`) {
		t.Fatal("allows come after the services")
	}
}

func TestIPRulesValidation(t *testing.T) {
	cases := map[string]IPRule{
		"block without ports": {ID: "x", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "block"},
		"ports without proto": {ID: "x", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "allow", Ports: []PortRange{{1, 2}}},
		"unknown action":      {ID: "x", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "deny", Proto: TCP, Ports: []PortRange{{1, 2}}},
		"injection in id":     {ID: `x" accept`, Prefix: netip.MustParsePrefix("192.0.2.1/32"), Action: "allow"},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			rs := fullRuleset()
			rs.IPRules = []IPRule{r}
			if _, err := Compile(rs, testNow); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestGuardRefusesPortBlockOfOperator(t *testing.T) {
	rs := ipRulesRuleset()
	p := Protection{SSHPorts: []uint16{22}, Addrs: []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.7")}}
	if err := CheckProtection(rs, p, testNow); err == nil {
		t.Fatal("blocking the operator's address on any port must be refused (IPv4-mapped included)")
	}
}

func TestIPRulesLoadInKernel(t *testing.T) {
	if os.Getenv("NFT_CHECK") != "1" {
		t.Skip("set NFT_CHECK=1 to validate against the kernel")
	}
	script, err := Compile(ipRulesRuleset(), testNow)
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

- [ ] **Step 3: Testi işlət və uğursuz olduğunu gör.** Expected: build FAIL, `undefined: IPRule`.

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 go test ./internal/netctl/nft/ -v
```

- [ ] **Step 4: Dörd faylı tam əvəz et**

`model.go`:
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

// IPRule is a per-source input rule: a port-scoped block (drop) or an allow
// (accept). Whole-address blocks without ports belong in Blocked.
type IPRule struct {
	ID     string
	Prefix netip.Prefix
	Action string      // "block" or "allow"
	Proto  Protocol    // tcp, udp, or "" for any protocol
	Ports  []PortRange // empty means every port; requires tcp or udp when set
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
	IPRules         []IPRule
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
`validate.go`:
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
		if f.Proto == UDP {
			for _, wg := range wireGuardRanges(rs) {
				if f.PublicPort >= wg.From && f.PublicPort <= wg.To {
					return fmt.Errorf("forward %s: public port %d is a WireGuard port", f.ID, f.PublicPort)
				}
			}
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
	for _, r := range rs.IPRules {
		if !idRe.MatchString(r.ID) {
			return fmt.Errorf("invalid IP rule id %q", r.ID)
		}
		if !r.Prefix.IsValid() {
			return fmt.Errorf("IP rule %s: invalid prefix", r.ID)
		}
		if r.Action != "block" && r.Action != "allow" {
			return fmt.Errorf("IP rule %s: action must be block or allow", r.ID)
		}
		if r.Proto != "" && r.Proto != TCP && r.Proto != UDP {
			return fmt.Errorf("IP rule %s: protocol must be tcp, udp or empty", r.ID)
		}
		if len(r.Ports) > 0 && r.Proto == "" {
			return fmt.Errorf("IP rule %s: ports need tcp or udp", r.ID)
		}
		if r.Action == "block" && len(r.Ports) == 0 {
			return fmt.Errorf("IP rule %s: whole-address blocks belong in the blocked set", r.ID)
		}
		for _, p := range r.Ports {
			if p.From == 0 || p.To < p.From {
				return fmt.Errorf("IP rule %s: invalid port range %s", r.ID, p)
			}
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

// ValidInterfaceName reports whether name is a Linux interface name that can
// be rendered safely into the ruleset.
func ValidInterfaceName(name string) bool {
	return ifaceRe.MatchString(name)
}
```
`compile.go`:
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
	// Port-scoped blocks also cut existing connections, like whole blocks.
	for _, r := range rs.IPRules {
		if r.Action == "block" {
			b.line(2, ipRuleLine(r, "counter drop"))
		}
	}
	b.line(2, "ct state established,related accept")
	b.line(2, "ct state invalid drop")
	b.line(2, "tcp dport @ssh_ports accept")
	b.line(2, "udp dport @wg_ports accept")
	// DHCPv6 replies come from the server's link-local address to a multicast
	// solicit, so conntrack cannot match them as established.
	b.line(2, `ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept comment "dhcpv6 client"`)
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, AdminInterface, joinPorts(AdminPorts)))
	b.line(2, fmt.Sprintf(`iifname %q tcp dport { %s } accept`, VPNInterfacePattern, joinPorts(APIPorts)))
	for _, s := range rs.Services {
		for _, l := range serviceLines(s) {
			b.line(2, l)
		}
	}
	for _, r := range rs.IPRules {
		if r.Action == "allow" {
			b.line(2, ipRuleLine(r, "accept"))
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

// ipRuleLine renders one IPRule with the given verdict, e.g.
// `ip saddr 203.0.113.5 tcp dport { 80, 443 } counter drop comment "ip:x"`.
func ipRuleLine(r IPRule, verdict string) string {
	family := "ip"
	if !r.Prefix.Addr().Is4() {
		family = "ip6"
	}
	parts := []string{family + " saddr " + elemPrefix(r.Prefix.Masked())}
	switch {
	case len(r.Ports) > 0:
		parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Proto, strings.Join(rangeElems(r.Ports), ", ")))
	case r.Proto != "":
		parts = append(parts, "meta l4proto "+string(r.Proto))
	}
	parts = append(parts, verdict, fmt.Sprintf("comment %q", "ip:"+r.ID))
	return strings.Join(parts, " ")
}

func writeForward(b *builder, rs Ruleset) {
	b.line(1, "chain forward {")
	b.line(2, "type filter hook forward priority filter - 10; policy accept;")
	b.line(2, "ip saddr @blocked_v4 counter drop")
	b.line(2, "ip6 saddr @blocked_v6 counter drop")
	b.line(2, "ct state established,related accept")
	// Docker publishes postgres on all addresses and DNATs it to the
	// container, so it passes forward, not input: the admin VPN keeps access,
	// every other interface (public, LAN, IPv6) loses it.
	b.line(2, fmt.Sprintf(`iifname %q meta l4proto tcp ct original proto-dst 5432 ct status dnat accept comment "admin VPN to docker-published postgres"`, AdminInterface))
	b.line(2, `meta l4proto tcp ct original proto-dst 5432 ct status dnat counter drop comment "docker-published postgres"`)
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
			// nft rejects timeouts of several years; longer bans stay in the
			// set without a timeout and are removed by a later reconcile.
			if secs <= maxElementTimeout {
				el += fmt.Sprintf(" timeout %ds", secs)
			}
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	return v4, v6
}

// maxElementTimeout is the longest set-element timeout rendered (365 days);
// nft 1.0.2–1.0.9 reject multi-year values with "value too large".
const maxElementTimeout = 365 * 24 * 3600

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
`guard.go`:
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
		addr = addr.Unmap()
		for _, r := range rs.IPRules {
			if r.Action == "block" && r.Prefix.Contains(addr) {
				return fmt.Errorf("IP rule %s would block the current session from %s", r.ID, addr)
			}
		}
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

- [ ] **Step 5: Tam yoxlama (kernel daxil).** Expected: `ok …/netctl/nft`, `TestIPRulesLoadInKernel` PASS.

```bash
MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v gomod:/go/pkg/mod -v /mnt/c/Users/Administrator/Desktop/NovusGate/server:/src -w /src golang:1.23 bash scripts/test-in-docker.sh
```

- [ ] **Step 6: Commit**

```bash
git add .gitattributes server/internal/netctl/nft/
git commit -m "feat: add per-source allow and port-scoped block rules to the nft engine"
```

---

### Task 2: DB cədvəlləri, modellər və store

**Files:**
- Create: `server/internal/controlplane/store/migrations_sql/006_firewall_engine.sql`
- Create: `server/internal/controlplane/store/migrations_rollback/006_firewall_engine.down.sql`
- Create: `server/internal/controlplane/store/firewall.go`
- Create: `server/internal/controlplane/store/firewall_test.go`
- Create: `server/scripts/test-with-postgres.sh`
- Modify: `server/internal/shared/models/models.go` (faylın sonuna əlavə)
- Modify: `server/scripts/test-in-docker.sh` (son sətir)

**Interfaces:**
- Produces:
  - Modellər: `models.FirewallService`, `models.FirewallIPRule`, `models.FirewallForward`.
  - Store metodları:
    - `ListFirewallServices`, `CreateFirewallService`, `DeleteFirewallService`;
    - `ListFirewallIPRules`, `CreateFirewallIPRule`, `DeleteFirewallIPRule`;
    - `ListFirewallForwards`, `CreateFirewallForward`, `DeleteFirewallForward`;
    - `ListEgressNodeIDs`, `SetNodeEgress`;
    - `ResetFirewallHostRules`;
    - `GetFirewallMeta`, `SetFirewallMeta`;
    - `ImportFirewallRules(ctx, services, rules, metaKey, metaValue)` (tək tranzaksiya).
  - Testlər üçün env: `TEST_DATABASE_URL`.

- [ ] **Step 1: Test köməkçi skriptini yarat** (`scripts/test-with-postgres.sh`)

```bash
#!/bin/bash
# Runs scripts/test-in-docker.sh against a disposable Postgres, so database
# tests (TEST_DATABASE_URL) run too. Run on the Windows dev machine from Git Bash:
#   bash server/scripts/test-with-postgres.sh
# SERVER_DIR is the server directory as seen by Docker inside WSL.
set -euo pipefail

SERVER_DIR="${SERVER_DIR:-/mnt/c/Users/Administrator/Desktop/NovusGate/server}"
NET=novusgate-test-net
PG=novusgate-test-pg

cleanup() {
  docker rm -f "$PG" > /dev/null 2>&1 || true
  docker network rm "$NET" > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NET" > /dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=ng -e POSTGRES_PASSWORD=ng -e POSTGRES_DB=ng postgres:16-alpine > /dev/null
for _ in $(seq 1 30); do
  if docker exec "$PG" pg_isready -U ng > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN --network "$NET" \
  -e TEST_DATABASE_URL="postgres://ng:ng@$PG:5432/ng?sslmode=disable" \
  -v gomod:/go/pkg/mod -v "$SERVER_DIR":/src -w /src \
  golang:1.23 bash scripts/test-in-docker.sh
```

`scripts/test-in-docker.sh`-ın son sətrini (`NFT_CHECK=1 go test ./... -count=1`) bununla əvəz et:
```bash
# -p 1: packages share one test database (TEST_DATABASE_URL) and must not run in parallel.
NFT_CHECK=1 go test -p 1 ./... -count=1
```

- [ ] **Step 2: Uğursuz testi yaz** (`store/firewall_test.go`)

```go
package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// newTestStore connects to TEST_DATABASE_URL (a disposable database), runs
// all migrations and empties the firewall tables. Skips without it.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run database tests (scripts/test-with-postgres.sh)")
	}
	s, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"fw_services", "fw_ip_rules", "fw_forwards", "fw_egress", "fw_meta"} {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestFirewallServicesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	svc := &models.FirewallService{Protocol: "tcp", PortFrom: 8000, PortTo: 8100,
		Sources: []string{"203.0.113.0/24", "2001:db8::/32"}, Interface: "eth0", Comment: "builds"}
	if err := s.CreateFirewallService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallService(ctx, &models.FirewallService{Protocol: "udp", PortFrom: 53, PortTo: 53}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListFirewallServices(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if got[0].ID != svc.ID || len(got[0].Sources) != 2 || got[0].Interface != "eth0" || got[0].Comment != "builds" {
		t.Fatalf("round trip lost data: %+v", got[0])
	}
	if got[1].Sources == nil || len(got[1].Sources) != 0 {
		t.Fatalf("no sources must read back as an empty list, got %#v", got[1].Sources)
	}
	if err := s.CreateFirewallService(ctx, &models.FirewallService{Protocol: "tcp", PortFrom: 90, PortTo: 80}); err == nil {
		t.Fatal("the schema must reject an inverted port range")
	}
	if err := s.DeleteFirewallService(ctx, svc.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFirewallServices(ctx); len(got) != 1 {
		t.Fatalf("delete failed: %v", got)
	}
}

func TestFirewallIPRulesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := s.CreateFirewallIPRule(ctx, &models.FirewallIPRule{Action: "block", Prefix: "203.0.113.7/32",
		Protocol: "tcp", Ports: "80,443", ExpiresAt: &in, Origin: "fail2ban"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallIPRule(ctx, &models.FirewallIPRule{Action: "allow", Prefix: "2001:db8::/48"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListFirewallIPRules(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if got[0].Prefix != "203.0.113.7/32" || got[0].Ports != "80,443" || got[0].Origin != "fail2ban" ||
		got[0].ExpiresAt == nil || !got[0].ExpiresAt.Equal(in) {
		t.Fatalf("block lost data: %+v", got[0])
	}
	if got[1].Origin != "panel" || got[1].ExpiresAt != nil || got[1].Protocol != "" {
		t.Fatalf("allow defaults wrong: %+v", got[1])
	}
	if err := s.CreateFirewallIPRule(ctx, &models.FirewallIPRule{Action: "block", Prefix: "10.0.0.5/24"}); err == nil {
		t.Fatal("the schema must reject a prefix with host bits set")
	}
	if err := s.ResetFirewallHostRules(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFirewallIPRules(ctx); len(got) != 0 {
		t.Fatalf("reset left %v", got)
	}
}

func TestFirewallForwardsEgressAndMeta(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	f := &models.FirewallForward{Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.5", TargetPort: 80}
	if err := s.CreateFirewallForward(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirewallForward(ctx, &models.FirewallForward{Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.6", TargetPort: 80}); err == nil {
		t.Fatal("two forwards on the same public port must be rejected")
	}
	got, err := s.ListFirewallForwards(ctx)
	if err != nil || len(got) != 1 || got[0].TargetIP != "10.20.0.5" {
		t.Fatalf("forwards = %v, %v", got, err)
	}

	// Egress rows reference nodes; create a network and node to point at.
	var netID, nodeID string
	if err := s.db.QueryRowContext(ctx, `INSERT INTO networks (name, cidr) VALUES ('fw-test', '10.77.0.0/24')
		ON CONFLICT (name) DO UPDATE SET cidr = EXCLUDED.cidr RETURNING id`).Scan(&netID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `INSERT INTO nodes (network_id, name, virtual_ip, public_key)
		VALUES ($1, 'fw-node', '10.77.0.9', 'KEY') ON CONFLICT (network_id, name) DO UPDATE SET public_key = 'KEY' RETURNING id`, netID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeEgress(ctx, nodeID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeEgress(ctx, nodeID, true); err != nil {
		t.Fatal("enabling twice must be idempotent")
	}
	if ids, _ := s.ListEgressNodeIDs(ctx); len(ids) != 1 || ids[0] != nodeID {
		t.Fatalf("egress = %v", ids)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.ListEgressNodeIDs(ctx); len(ids) != 0 {
		t.Fatal("deleting a node must remove its egress permission")
	}

	if _, ok, err := s.GetFirewallMeta(ctx, "iptables_imported"); err != nil || ok {
		t.Fatalf("missing meta must report ok=false, got %v %v", ok, err)
	}
	if err := s.SetFirewallMeta(ctx, "iptables_imported", "2026-10-13"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFirewallMeta(ctx, "iptables_imported", "again"); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.GetFirewallMeta(ctx, "iptables_imported"); err != nil || !ok || v != "again" {
		t.Fatalf("meta = %q %v %v", v, ok, err)
	}
}

func TestImportFirewallRulesIsAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	good := []*models.FirewallService{{Protocol: "tcp", PortFrom: 443, PortTo: 443}}
	bad := []*models.FirewallIPRule{{Action: "block", Prefix: "not-a-cidr"}}
	if err := s.ImportFirewallRules(ctx, good, bad, "iptables_imported", "x"); err == nil {
		t.Fatal("an invalid rule must fail the import")
	}
	if got, _ := s.ListFirewallServices(ctx); len(got) != 0 {
		t.Fatal("a failed import must not leave partial rows")
	}
	if _, ok, _ := s.GetFirewallMeta(ctx, "iptables_imported"); ok {
		t.Fatal("a failed import must not set the marker")
	}
	ok := []*models.FirewallIPRule{{Action: "block", Prefix: "198.51.100.9/32"}}
	if err := s.ImportFirewallRules(ctx, good, ok, "iptables_imported", "done"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFirewallIPRules(ctx); len(got) != 1 || got[0].Origin != "import" {
		t.Fatalf("imported rules = %+v", got)
	}
	if v, ok, _ := s.GetFirewallMeta(ctx, "iptables_imported"); !ok || v != "done" {
		t.Fatal("the marker must be set with the rows")
	}
}
```

- [ ] **Step 3: RED.** `bash server/scripts/test-with-postgres.sh`. Expected: build FAIL, `undefined: models.FirewallService` / `s.CreateFirewallService undefined`.

- [ ] **Step 4: Migration və rollback**

`006_firewall_engine.sql`:
```sql
-- Migration: 006_firewall_engine.sql
-- Purpose: state owned by the nftables firewall engine (P3b). Additive only;
-- rollback: internal/controlplane/store/migrations_rollback/006_firewall_engine.down.sql

-- Host ports opened by the panel (input chain).
CREATE TABLE IF NOT EXISTS fw_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    protocol VARCHAR(3) NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port_from INT NOT NULL CHECK (port_from BETWEEN 1 AND 65535),
    port_to INT NOT NULL CHECK (port_to BETWEEN 1 AND 65535 AND port_to >= port_from),
    sources TEXT[] NOT NULL DEFAULT '{}',
    interface VARCHAR(15),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-source blocks and allows; blocks without ports go to the blocked set.
CREATE TABLE IF NOT EXISTS fw_ip_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(5) NOT NULL CHECK (action IN ('block', 'allow')),
    prefix CIDR NOT NULL,
    protocol VARCHAR(3) CHECK (protocol IN ('tcp', 'udp')),
    ports TEXT,
    expires_at TIMESTAMPTZ,
    origin VARCHAR(10) NOT NULL DEFAULT 'panel' CHECK (origin IN ('panel', 'fail2ban', 'import')),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fw_ip_rules_expires ON fw_ip_rules(expires_at);

-- Public port -> VPN node port forwards.
CREATE TABLE IF NOT EXISTS fw_forwards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    protocol VARCHAR(3) NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    public_port INT NOT NULL CHECK (public_port BETWEEN 1 AND 65535),
    target_ip INET NOT NULL,
    target_port INT NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (protocol, public_port)
);

-- Nodes allowed to reach the internet through the server (full tunnel).
CREATE TABLE IF NOT EXISTS fw_egress (
    node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Engine bookkeeping, e.g. whether iptables rules were imported.
CREATE TABLE IF NOT EXISTS fw_meta (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```
`migrations_rollback/006_firewall_engine.down.sql`:
```sql
-- Rollback for 006_firewall_engine.sql. Run manually with psql, then delete the
-- schema_migrations row so the migration can be re-applied later:
--   DELETE FROM schema_migrations WHERE version = '006_firewall_engine.sql';
-- This removes all firewall-engine state (services, IP rules, forwards, egress).
BEGIN;
DROP TABLE IF EXISTS fw_meta;
DROP TABLE IF EXISTS fw_egress;
DROP TABLE IF EXISTS fw_forwards;
DROP TABLE IF EXISTS fw_ip_rules;
DROP TABLE IF EXISTS fw_services;
DELETE FROM schema_migrations WHERE version = '006_firewall_engine.sql';
COMMIT;
```

- [ ] **Step 5: Modelləri `models.go`-nun sonuna əlavə et**

```go

// FirewallService opens a host port through the nftables engine.
type FirewallService struct {
	ID        string    `json:"id"`
	Protocol  string    `json:"protocol"` // tcp or udp
	PortFrom  int       `json:"port_from"`
	PortTo    int       `json:"port_to"`
	Sources   []string  `json:"sources"` // IPs or CIDRs; empty means any source
	Interface string    `json:"interface,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// FirewallIPRule blocks or allows a source address, optionally on some ports.
type FirewallIPRule struct {
	ID        string     `json:"id"`
	Action    string     `json:"action"`             // block or allow
	Prefix    string     `json:"prefix"`             // CIDR, e.g. 203.0.113.7/32
	Protocol  string     `json:"protocol,omitempty"` // tcp, udp or empty
	Ports     string     `json:"ports,omitempty"`    // e.g. "80,443,8000-8100"
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Origin    string     `json:"origin"` // panel, fail2ban or import
	Comment   string     `json:"comment,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// FirewallForward publishes a VPN node's port on the server's public address.
type FirewallForward struct {
	ID         string    `json:"id"`
	Protocol   string    `json:"protocol"` // tcp or udp
	PublicPort int       `json:"public_port"`
	TargetIP   string    `json:"target_ip"`
	TargetPort int       `json:"target_port"`
	Comment    string    `json:"comment,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
```

- [ ] **Step 6: Store metodları** (`store/firewall.go`)

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// ListFirewallServices returns the panel-opened host ports, oldest first.
func (s *Store) ListFirewallServices(ctx context.Context) ([]*models.FirewallService, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, protocol, port_from, port_to, sources, COALESCE(interface, ''), COALESCE(comment, ''), created_at
		FROM fw_services ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallService{}
	for rows.Next() {
		svc := &models.FirewallService{}
		if err := rows.Scan(&svc.ID, &svc.Protocol, &svc.PortFrom, &svc.PortTo, pq.Array(&svc.Sources),
			&svc.Interface, &svc.Comment, &svc.CreatedAt); err != nil {
			return nil, err
		}
		if svc.Sources == nil {
			svc.Sources = []string{}
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

// CreateFirewallService stores a service; an empty ID gets a new UUID.
func (s *Store) CreateFirewallService(ctx context.Context, svc *models.FirewallService) error {
	if svc.ID == "" {
		svc.ID = uuid.New().String()
	}
	if svc.Sources == nil {
		svc.Sources = []string{}
	}
	svc.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_services (id, protocol, port_from, port_to, sources, interface, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		svc.ID, svc.Protocol, svc.PortFrom, svc.PortTo, pq.Array(svc.Sources),
		nullString(svc.Interface), nullString(svc.Comment), svc.CreatedAt)
	return err
}

// DeleteFirewallService removes a service; a missing ID is not an error.
func (s *Store) DeleteFirewallService(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_services WHERE id = $1`, id)
	return err
}

// ListFirewallIPRules returns all blocks and allows, oldest first.
func (s *Store) ListFirewallIPRules(ctx context.Context) ([]*models.FirewallIPRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, action, prefix::text, COALESCE(protocol, ''), COALESCE(ports, ''), expires_at, origin, COALESCE(comment, ''), created_at
		FROM fw_ip_rules ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallIPRule{}
	for rows.Next() {
		r := &models.FirewallIPRule{}
		var expires sql.NullTime
		if err := rows.Scan(&r.ID, &r.Action, &r.Prefix, &r.Protocol, &r.Ports, &expires, &r.Origin, &r.Comment, &r.CreatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateFirewallIPRule stores a block or allow; an empty ID gets a new UUID.
func (s *Store) CreateFirewallIPRule(ctx context.Context, r *models.FirewallIPRule) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	if r.Origin == "" {
		r.Origin = "panel"
	}
	r.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_ip_rules (id, action, prefix, protocol, ports, expires_at, origin, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.ID, r.Action, r.Prefix, nullString(r.Protocol), nullString(r.Ports), r.ExpiresAt, r.Origin, nullString(r.Comment), r.CreatedAt)
	return err
}

// DeleteFirewallIPRule removes a block or allow; a missing ID is not an error.
func (s *Store) DeleteFirewallIPRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_ip_rules WHERE id = $1`, id)
	return err
}

// ListFirewallForwards returns all port forwards, oldest first.
func (s *Store) ListFirewallForwards(ctx context.Context) ([]*models.FirewallForward, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, protocol, public_port, host(target_ip), target_port, COALESCE(comment, ''), created_at
		FROM fw_forwards ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.FirewallForward{}
	for rows.Next() {
		f := &models.FirewallForward{}
		if err := rows.Scan(&f.ID, &f.Protocol, &f.PublicPort, &f.TargetIP, &f.TargetPort, &f.Comment, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFirewallForward stores a forward; an empty ID gets a new UUID.
func (s *Store) CreateFirewallForward(ctx context.Context, f *models.FirewallForward) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	f.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_forwards (id, protocol, public_port, target_ip, target_port, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		f.ID, f.Protocol, f.PublicPort, f.TargetIP, f.TargetPort, nullString(f.Comment), f.CreatedAt)
	return err
}

// DeleteFirewallForward removes a forward; a missing ID is not an error.
func (s *Store) DeleteFirewallForward(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_forwards WHERE id = $1`, id)
	return err
}

// ListEgressNodeIDs returns the nodes allowed to use the server as internet exit.
func (s *Store) ListEgressNodeIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM fw_egress ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetNodeEgress allows or forbids a node to reach the internet through the server.
func (s *Store) SetNodeEgress(ctx context.Context, nodeID string, enabled bool) error {
	if enabled {
		_, err := s.db.ExecContext(ctx, `INSERT INTO fw_egress (node_id) VALUES ($1) ON CONFLICT (node_id) DO NOTHING`, nodeID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM fw_egress WHERE node_id = $1`, nodeID)
	return err
}

// ResetFirewallHostRules removes every service and IP rule in one transaction
// (the legacy "reset firewall" action); forwards and egress are kept.
func (s *Store) ResetFirewallHostRules(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM fw_services`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fw_ip_rules`); err != nil {
		return err
	}
	return tx.Commit()
}

// GetFirewallMeta reads an engine bookkeeping value.
func (s *Store) GetFirewallMeta(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM fw_meta WHERE key = $1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get firewall meta %s: %w", key, err)
	}
	return value, true, nil
}

// SetFirewallMeta writes an engine bookkeeping value.
func (s *Store) SetFirewallMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO fw_meta (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, key, value)
	return err
}

// ImportFirewallRules stores imported services and IP rules and records the
// import marker in one transaction, so a failed import can simply be retried.
func (s *Store) ImportFirewallRules(ctx context.Context, services []*models.FirewallService, rules []*models.FirewallIPRule, metaKey, metaValue string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	for _, svc := range services {
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
			return fmt.Errorf("import service %d/%s: %w", svc.PortFrom, svc.Protocol, err)
		}
	}
	for _, r := range rules {
		if r.ID == "" {
			r.ID = uuid.New().String()
		}
		if r.Origin == "" {
			r.Origin = "import"
		}
		r.CreatedAt = now
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fw_ip_rules (id, action, prefix, protocol, ports, expires_at, origin, comment, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			r.ID, r.Action, r.Prefix, nullString(r.Protocol), nullString(r.Ports), r.ExpiresAt, r.Origin, nullString(r.Comment), r.CreatedAt); err != nil {
			return fmt.Errorf("import IP rule %s: %w", r.Prefix, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO fw_meta (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, metaKey, metaValue); err != nil {
		return err
	}
	return tx.Commit()
}
```

- [ ] **Step 7: GREEN.** `bash server/scripts/test-with-postgres.sh`. Expected: `ok …/controlplane/store` (4 test real DB-də keçir, SKIP deyil).

- [ ] **Step 8: Commit**

```bash
git add server/internal/controlplane/store/ server/internal/shared/models/models.go server/scripts/
git commit -m "feat: store firewall engine state in additive tables"
```

---

### Task 3: Firewall Engine, iptables idxalı, host bağlantısı

**Files:**
- Create: `server/internal/controlplane/firewall/engine.go`, `engine_test.go`
- Create: `server/internal/controlplane/firewall/iptables_import.go`, `iptables_import_test.go`
- Create: `server/internal/controlplane/firewall/host.go`

**Interfaces:**
- Consumes: Task 1 (`nft.IPRule`), Task 2 (modellər, `ImportFirewallRules`), P3a (`BuildRuleset`, `DetectHost`, `ParsePorts`, `nft.SafeApplier`, `nft.NsenterRunner`).
- Produces:
  - `Mode` (`ModeIptables`, `ModeShadow`, `ModeNft`), `ParseMode`;
  - `ErrEngineDisabled`, `ErrRejected`;
  - `Store`, `HostInfo`, `State`, `Change{Mutate, Commit}`, `Result`;
  - `Engine{Mode, Store, Detect, Applier, Persist, Now, AfterFunc}` və metodları: `LoadState`, `Preview`, `Check`, `Propose(ctx, ch, confirm, protect)`, `Reconcile`, `Confirm`, `PendingChange`;
  - `ImportStore`, `ImportedKey`, `ImportIptables`, `ParseIptablesInput`;
  - `NewHostEngine(mode, store)`, `WriteHostFile`, `PersistPath`, `ConfirmTimeout`.

- [ ] **Step 1: Uğursuz testləri yaz**

`engine_test.go`:
```go
package firewall

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type memStore struct {
	networks []*models.Network
	services []*models.FirewallService
	ipRules  []*models.FirewallIPRule
	forwards []*models.FirewallForward
	egress   []string
	nodes    map[string]*models.Node
	meta     map[string]string
	imports  int
}

func (m *memStore) ListNetworks(context.Context) ([]*models.Network, error) { return m.networks, nil }
func (m *memStore) ListVPNFirewallRules(context.Context) ([]*models.VPNFirewallRule, error) {
	return nil, nil
}
func (m *memStore) GetNode(_ context.Context, id string) (*models.Node, error) {
	return m.nodes[id], nil
}
func (m *memStore) ListFirewallServices(context.Context) ([]*models.FirewallService, error) {
	return append([]*models.FirewallService(nil), m.services...), nil
}
func (m *memStore) ListFirewallIPRules(context.Context) ([]*models.FirewallIPRule, error) {
	return append([]*models.FirewallIPRule(nil), m.ipRules...), nil
}
func (m *memStore) ListFirewallForwards(context.Context) ([]*models.FirewallForward, error) {
	return m.forwards, nil
}
func (m *memStore) ListEgressNodeIDs(context.Context) ([]string, error) { return m.egress, nil }
func (m *memStore) GetFirewallMeta(_ context.Context, k string) (string, bool, error) {
	v, ok := m.meta[k]
	return v, ok, nil
}
func (m *memStore) ImportFirewallRules(_ context.Context, s []*models.FirewallService, r []*models.FirewallIPRule, k, v string) error {
	m.imports++
	m.services = append(m.services, s...)
	m.ipRules = append(m.ipRules, r...)
	if m.meta == nil {
		m.meta = map[string]string{}
	}
	m.meta[k] = v
	return nil
}

// nftRunner records nft invocations against a fake host.
type nftRunner struct {
	applied []string
	checked int
	iptS    string
}

func (r *nftRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	switch cmd {
	case "nft -f -":
		r.applied = append(r.applied, stdin)
	case "nft -c -f -":
		r.checked++
	case "nft list table inet novusgate":
		return "", errors.New("nft: Error: No such file or directory")
	case "iptables -S INPUT":
		return r.iptS, nil
	}
	return "", nil
}

type hostTimer struct{ active bool }

func (t *hostTimer) Arm(string, time.Duration) error { t.active = true; return nil }
func (t *hostTimer) Disarm() error                   { t.active = false; return nil }
func (t *hostTimer) Active() (bool, error)           { return t.active, nil }

var engineNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type harness struct {
	e         *Engine
	st        *memStore
	r         *nftRunner
	persisted []string
	rollback  func()
	expiryIn  time.Duration
}

func newHarness(mode Mode) *harness {
	h := &harness{
		st: &memStore{
			networks: []*models.Network{{ID: "n1", Name: "Office", CIDR: "10.20.0.0/24", InterfaceName: "wg1", ListenPort: 51821}},
			nodes:    map[string]*models.Node{"node-7": {ID: "node-7", VirtualIP: net.ParseIP("10.20.0.7")}},
		},
		r: &nftRunner{},
	}
	applier := &nft.SafeApplier{
		Exec: nft.Executor{Runner: h.r}, Timer: &hostTimer{}, Timeout: time.Minute,
		Now: func() time.Time { return engineNow },
		AfterFunc: func(_ time.Duration, f func()) func() bool {
			h.rollback = f
			return func() bool { h.rollback = nil; return true }
		},
	}
	h.e = &Engine{
		Mode: mode, Store: h.st, Applier: applier, Now: func() time.Time { return engineNow },
		Detect:  func() (HostInfo, error) { return HostInfo{SSHPorts: []uint16{22}, Egress: "eth0"}, nil },
		Persist: func(s string) error { h.persisted = append(h.persisted, s); return nil },
		AfterFunc: func(d time.Duration, f func()) func() bool {
			h.expiryIn = d
			return func() bool { return true }
		},
	}
	return h
}

func openPort(h *harness, port int, commits *int) Change {
	svc := &models.FirewallService{ID: "11111111-1111-1111-1111-111111111111", Protocol: "tcp", PortFrom: port, PortTo: port, Sources: []string{}}
	return Change{
		Mutate: func(st *State) error { st.Services = append(st.Services, svc); return nil },
		Commit: func(context.Context) error { *commits++; h.st.services = append(h.st.services, svc); return nil },
	}
}

func TestEngineDisabledOutsideNftMode(t *testing.T) {
	for _, mode := range []Mode{ModeIptables, ModeShadow} {
		h := newHarness(mode)
		commits := 0
		if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); !errors.Is(err, ErrEngineDisabled) {
			t.Fatalf("%s: got %v, want ErrEngineDisabled", mode, err)
		}
		if len(h.r.applied) != 0 || commits != 0 {
			t.Fatalf("%s: nothing may be applied or stored", mode)
		}
	}
}

func TestProposeImmediateAppliesStoresAndPersists(t *testing.T) {
	h := newHarness(ModeNft)
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
	if err != nil || res.Pending != nil {
		t.Fatalf("Propose = %+v, %v", res, err)
	}
	if len(h.r.applied) != 1 || !strings.Contains(h.r.applied[0], `tcp dport 443 accept comment "svc:11111111-1111-1111-1111-111111111111"`) {
		t.Fatalf("applied = %v", h.r.applied)
	}
	if commits != 1 || len(h.persisted) != 1 || h.persisted[0] != h.r.applied[0] {
		t.Fatal("an immediate change must be stored once and persisted for boot")
	}
}

func TestProposeWithConfirmStoresOnlyAfterConfirm(t *testing.T) {
	h := newHarness(ModeNft)
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), true, nil)
	if err != nil || res.Pending == nil {
		t.Fatalf("Propose = %+v, %v", res, err)
	}
	if commits != 0 || len(h.persisted) != 0 {
		t.Fatal("nothing may be stored before confirmation")
	}
	if err := h.e.Confirm(context.Background(), res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	if commits != 1 || len(h.persisted) != 1 {
		t.Fatal("confirm must store and persist the change")
	}
}

func TestRolledBackChangeIsNeverStored(t *testing.T) {
	h := newHarness(ModeNft)
	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.rollback() // nobody confirmed in time

	if err := h.e.Confirm(context.Background(), res.Pending.ID); !errors.Is(err, nft.ErrNoPending) {
		t.Fatalf("confirm after rollback = %v, want ErrNoPending", err)
	}
	if commits != 0 || len(h.persisted) != 0 {
		t.Fatal("a rolled-back change must never reach the database or the boot ruleset")
	}
}

func TestProposeRefusesToBlockTheOperator(t *testing.T) {
	h := newHarness(ModeNft)
	block := Change{Mutate: func(st *State) error {
		st.IPRules = append(st.IPRules, &models.FirewallIPRule{ID: "22222222-2222-2222-2222-222222222222",
			Action: "block", Prefix: "203.0.113.0/24"})
		return nil
	}}
	_, err := h.e.Propose(context.Background(), block, false, []netip.Addr{netip.MustParseAddr("203.0.113.50")})
	if !errors.Is(err, ErrRejected) || len(h.r.applied) != 0 {
		t.Fatalf("blocking the operator must be rejected before anything is applied (err=%v)", err)
	}
}

func TestDesiredConvertsStoredState(t *testing.T) {
	h := newHarness(ModeNft)
	past := engineNow.Add(-time.Minute)
	soon := engineNow.Add(30 * time.Minute)
	h.st.ipRules = []*models.FirewallIPRule{
		{ID: "a1111111-1111-1111-1111-111111111111", Action: "block", Prefix: "198.51.100.9/32", ExpiresAt: &soon},
		{ID: "a2222222-2222-2222-2222-222222222222", Action: "block", Prefix: "203.0.113.7/32", Protocol: "tcp", Ports: "80,443"},
		{ID: "a3333333-3333-3333-3333-333333333333", Action: "allow", Prefix: "192.0.2.0/24"},
		{ID: "a4444444-4444-4444-4444-444444444444", Action: "block", Prefix: "192.0.2.200/32", ExpiresAt: &past},
	}
	h.st.forwards = []*models.FirewallForward{{ID: "f1111111-1111-1111-1111-111111111111", Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.5", TargetPort: 80}}
	h.st.egress = []string{"node-7"}

	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	got := h.r.applied[0]
	for _, want := range []string{
		"elements = { 198.51.100.9 timeout 1800s }",
		`ip saddr 203.0.113.7 tcp dport { 80, 443 } counter drop`,
		`ip saddr 192.0.2.0/24 accept`,
		`dnat ip to 10.20.0.5:80`,
		"elements = { 10.20.0.7 }",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(got, "192.0.2.200") {
		t.Error("expired rules must not be applied")
	}
	if h.expiryIn != 30*time.Minute+time.Second {
		t.Fatalf("reconcile must be scheduled for the next expiry, got %v", h.expiryIn)
	}
}

// An invalid stored row (e.g. imported from iptables) must not block every
// change, but the same mistake in a new change must be rejected.
func TestInvalidStoredRowWarnsButInvalidChangeIsRejected(t *testing.T) {
	h := newHarness(ModeNft)
	h.st.services = []*models.FirewallService{{ID: "b1111111-1111-1111-1111-111111111111",
		Protocol: "tcp", PortFrom: 8443, PortTo: 8443, Sources: []string{"203.0.113.0/24"}}}

	commits := 0
	res, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
	if err != nil {
		t.Fatalf("a stale invalid row must not block a valid change: %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(h.r.applied[0], "tcp dport 443 accept") || strings.Contains(h.r.applied[0], "svc:b1111111") {
		t.Fatalf("warnings=%v\n%s", res.Warnings, h.r.applied[0])
	}

	bad := Change{Mutate: func(st *State) error {
		st.Services = append(st.Services, &models.FirewallService{ID: "b2222222-2222-2222-2222-222222222222",
			Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Sources: []string{}})
		return nil
	}}
	if _, err := h.e.Propose(context.Background(), bad, false, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("opening a reserved admin port publicly must be rejected, got %v", err)
	}
}

func TestShadowCheckDoesNotApply(t *testing.T) {
	h := newHarness(ModeShadow)
	if _, err := h.e.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.r.checked != 1 || len(h.r.applied) != 0 {
		t.Fatal("shadow mode may only run nft -c")
	}
}

func TestImportIptablesRunsOnce(t *testing.T) {
	h := newHarness(ModeNft)
	h.r.iptS = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n-A INPUT -s 198.51.100.9/32 -j DROP\n"
	n, _, err := ImportIptables(context.Background(), h.st, h.r, []uint16{22}, engineNow)
	if err != nil || n != 2 {
		t.Fatalf("import = %d, %v", n, err)
	}
	if n, _, _ := ImportIptables(context.Background(), h.st, h.r, []uint16{22}, engineNow); n != 0 || h.st.imports != 1 {
		t.Fatal("the import must run only once")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeIptables, "NFT": ModeNft, " shadow ": ModeShadow} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("nftables"); err == nil {
		t.Error("unknown modes must be rejected")
	}
}
```
`iptables_import_test.go`:
```go
package firewall

import (
	"strings"
	"testing"
)

// `iptables -S INPUT` after setup-firewall.sh, panel actions and fail2ban.
const iptablesInput = `-P INPUT DROP
-A INPUT -s 198.51.100.9/32 -j DROP
-A INPUT -s 203.0.113.7/32 -p tcp -m multiport --dports 80,443 -j DROP
-A INPUT -s 192.0.2.0/24 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT
-A INPUT -p udp -m udp --dport 51820:51900 -j ACCEPT
-A INPUT -i wg0 -p tcp -m tcp --dport 3007 -j ACCEPT
-A INPUT -i wg+ -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3007 -j DROP
-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 8443 -j ACCEPT
-A INPUT -p udp -m udp --dport 60000:60010 -j ACCEPT
`

func TestParseIptablesInput(t *testing.T) {
	services, ipRules, skipped := ParseIptablesInput(iptablesInput, []uint16{22, 2222})

	if len(services) != 3 {
		t.Fatalf("services = %d, want 3 (443, 8443 from 203.0.113.0/24, udp 60000-60010)", len(services))
	}
	if s := services[0]; s.Protocol != "tcp" || s.PortFrom != 443 || len(s.Sources) != 0 {
		t.Fatalf("open port 443: %+v", s)
	}
	if s := services[1]; s.PortFrom != 8443 || len(s.Sources) != 1 || s.Sources[0] != "203.0.113.0/24" {
		t.Fatalf("sourced port: %+v", s)
	}
	if s := services[2]; s.Protocol != "udp" || s.PortFrom != 60000 || s.PortTo != 60010 {
		t.Fatalf("udp range opened from the panel: %+v", s)
	}

	if len(ipRules) != 3 {
		t.Fatalf("ip rules = %d, want 3", len(ipRules))
	}
	if r := ipRules[0]; r.Action != "block" || r.Prefix != "198.51.100.9/32" || r.Ports != "" || r.Origin != "import" {
		t.Fatalf("whole block: %+v", r)
	}
	if r := ipRules[1]; r.Action != "block" || r.Protocol != "tcp" || r.Ports != "80,443" {
		t.Fatalf("port block: %+v", r)
	}
	if r := ipRules[2]; r.Action != "allow" || r.Prefix != "192.0.2.0/24" {
		t.Fatalf("allow: %+v", r)
	}

	for _, must := range []string{"f2b-sshd", "-i lo", "RELATED,ESTABLISHED", "--dport 22 -j ACCEPT",
		"--dport 2222 -j ACCEPT", "51820:51900", "-i wg0", "--dport 3007 -j DROP", "icmp"} {
		found := false
		for _, s := range skipped {
			if strings.Contains(s, must) {
				found = true
			}
		}
		if !found {
			t.Errorf("installer/foreign rule %q must be skipped", must)
		}
	}
}
```

- [ ] **Step 2: RED.** `go test ./internal/controlplane/firewall/ -v` (DB-siz əmr). Expected: build FAIL, `undefined: Engine`, `undefined: ParseIptablesInput`.

- [ ] **Step 3: Implementasiya**

`engine.go`:
```go
package firewall

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Mode selects who enforces the host firewall (FIREWALL_ENGINE).
type Mode string

const (
	// ModeIptables keeps the legacy iptables code paths only (default).
	ModeIptables Mode = "iptables"
	// ModeShadow keeps iptables enforcing; the engine only compiles and checks.
	ModeShadow Mode = "shadow"
	// ModeNft makes the engine enforce table inet novusgate.
	ModeNft Mode = "nft"
)

// ParseMode reads FIREWALL_ENGINE; empty means iptables.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "", ModeIptables:
		return ModeIptables, nil
	case ModeShadow, ModeNft:
		return m, nil
	}
	return "", fmt.Errorf("unknown FIREWALL_ENGINE %q (use iptables, shadow or nft)", s)
}

var (
	// ErrEngineDisabled is returned for engine changes outside nft mode.
	ErrEngineDisabled = errors.New("the nftables firewall engine is not enabled (FIREWALL_ENGINE=nft)")
	// ErrRejected wraps changes refused before touching the host: an invalid
	// ruleset or one that would lock the operator out.
	ErrRejected = errors.New("firewall change rejected")
)

// Store is everything the engine reads.
type Store interface {
	Source
	ListFirewallServices(ctx context.Context) ([]*models.FirewallService, error)
	ListFirewallIPRules(ctx context.Context) ([]*models.FirewallIPRule, error)
	ListFirewallForwards(ctx context.Context) ([]*models.FirewallForward, error)
	ListEgressNodeIDs(ctx context.Context) ([]string, error)
}

// HostInfo are the host facts a ruleset depends on.
type HostInfo struct {
	SSHPorts []uint16
	Egress   string
}

// State is the stored firewall state before compilation.
type State struct {
	Services      []*models.FirewallService
	IPRules       []*models.FirewallIPRule
	Forwards      []*models.FirewallForward
	EgressNodeIDs []string
}

// Change is an edit proposed through the engine. Mutate applies it to a copy
// of the stored state; Commit writes it to the database once it is live
// (immediately, or after confirmation). Nothing is stored for a change that
// is rolled back, so the database and the kernel never diverge.
type Change struct {
	Mutate func(st *State) error
	Commit func(ctx context.Context) error
}

// Result reports what Propose did.
type Result struct {
	Pending  *nft.Pending
	Warnings []error
}

// Engine owns table inet novusgate.
type Engine struct {
	Mode      Mode
	Store     Store
	Detect    func() (HostInfo, error)
	Applier   *nft.SafeApplier
	Persist   func(script string) error // writes the boot-time ruleset on the host
	Now       func() time.Time
	AfterFunc func(time.Duration, func()) func() bool

	mu         sync.Mutex
	pending    *pendingCommit
	stopExpiry func() bool
}

type pendingCommit struct {
	id     string
	commit func(ctx context.Context) error
	script string
	state  State
}

// LoadState reads the stored firewall state.
func (e *Engine) LoadState(ctx context.Context) (State, error) {
	var st State
	var err error
	if st.Services, err = e.Store.ListFirewallServices(ctx); err != nil {
		return st, fmt.Errorf("list services: %w", err)
	}
	if st.IPRules, err = e.Store.ListFirewallIPRules(ctx); err != nil {
		return st, fmt.Errorf("list IP rules: %w", err)
	}
	if st.Forwards, err = e.Store.ListFirewallForwards(ctx); err != nil {
		return st, fmt.Errorf("list forwards: %w", err)
	}
	if st.EgressNodeIDs, err = e.Store.ListEgressNodeIDs(ctx); err != nil {
		return st, fmt.Errorf("list egress nodes: %w", err)
	}
	return st, nil
}

// Preview compiles the stored state without touching the host (any mode).
func (e *Engine) Preview(ctx context.Context) (string, []error, error) {
	st, err := e.LoadState(ctx)
	if err != nil {
		return "", nil, err
	}
	rs, _, warnings, err := e.desired(ctx, st)
	if err != nil {
		return "", warnings, err
	}
	script, err := nft.Compile(rs, e.Now())
	return script, warnings, err
}

// Check compiles the stored state and validates it with `nft -c` (shadow mode).
func (e *Engine) Check(ctx context.Context) ([]error, error) {
	script, warnings, err := e.Preview(ctx)
	if err != nil {
		return warnings, err
	}
	return warnings, e.Applier.Exec.Check(script)
}

// Propose applies a change. confirm=true keeps it pending until Confirm (and
// rolls it back otherwise); confirm=false makes it final immediately. The
// operator's addresses in protect must stay reachable.
func (e *Engine) Propose(ctx context.Context, ch Change, confirm bool, protect []netip.Addr) (Result, error) {
	if e.Mode != ModeNft {
		return Result{}, ErrEngineDisabled
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	st, err := e.LoadState(ctx)
	if err != nil {
		return Result{}, err
	}
	var before map[string]bool
	if ch.Mutate != nil {
		// Stored rows that are invalid only warn; an invalid new entry must
		// be rejected, so remember which warnings existed before the change.
		_, _, old, err := e.desired(ctx, st)
		if err != nil {
			return Result{Warnings: old}, err
		}
		before = map[string]bool{}
		for _, w := range old {
			before[w.Error()] = true
		}
		if err := ch.Mutate(&st); err != nil {
			return Result{}, err
		}
	}
	rs, host, warnings, err := e.desired(ctx, st)
	if err != nil {
		return Result{Warnings: warnings}, err
	}
	if before != nil {
		for _, w := range warnings {
			if !before[w.Error()] {
				return Result{Warnings: warnings}, fmt.Errorf("%w: %v", ErrRejected, w)
			}
		}
	}
	if err := nft.CheckProtection(rs, nft.Protection{SSHPorts: host.SSHPorts, Addrs: protect}, e.Now()); err != nil {
		return Result{Warnings: warnings}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	script, err := nft.Compile(rs, e.Now())
	if err != nil {
		return Result{Warnings: warnings}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	p, err := e.Applier.Apply(script, confirm)
	if err != nil {
		return Result{Warnings: warnings}, err
	}
	if confirm {
		e.pending = &pendingCommit{id: p.ID, commit: ch.Commit, script: script, state: st}
		return Result{Pending: &p, Warnings: warnings}, nil
	}
	return Result{Warnings: warnings}, e.finish(ctx, ch.Commit, script, st)
}

// Reconcile re-applies the stored state immediately.
func (e *Engine) Reconcile(ctx context.Context, protect []netip.Addr) (Result, error) {
	return e.Propose(ctx, Change{}, false, protect)
}

// Confirm makes a pending change final and stores it.
func (e *Engine) Confirm(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.Applier.Confirm(id); err != nil {
		// A rolled-back change is never stored; drop its commit.
		if (errors.Is(err, nft.ErrExpired) || errors.Is(err, nft.ErrNoPending)) && e.pending != nil && e.pending.id == id {
			e.pending = nil
		}
		return err
	}
	pc := e.pending
	e.pending = nil
	if pc == nil || pc.id != id {
		return nil
	}
	return e.finish(ctx, pc.commit, pc.script, pc.state)
}

// PendingChange reports the change waiting for confirmation, if any.
func (e *Engine) PendingChange() (nft.Pending, bool) {
	return e.Applier.PendingChange()
}

func (e *Engine) finish(ctx context.Context, commit func(context.Context) error, script string, st State) error {
	if commit != nil {
		if err := commit(ctx); err != nil {
			// The next reconcile restores the stored state on the host.
			return fmt.Errorf("firewall change applied but not saved: %w", err)
		}
	}
	e.scheduleExpiry(st)
	if e.Persist != nil {
		if err := e.Persist(script); err != nil {
			return fmt.Errorf("firewall applied but the boot-time ruleset was not written: %w", err)
		}
	}
	return nil
}

// scheduleExpiry re-runs reconcile when the next IP rule expires, so rules the
// kernel cannot time out on its own (port-scoped rules, allows, bans longer
// than nft's timeout limit) are removed on time.
func (e *Engine) scheduleExpiry(st State) {
	if e.AfterFunc == nil {
		return
	}
	if e.stopExpiry != nil {
		e.stopExpiry()
		e.stopExpiry = nil
	}
	now := e.Now()
	var next *time.Time
	for _, r := range st.IPRules {
		if r.ExpiresAt != nil && r.ExpiresAt.After(now) && (next == nil || r.ExpiresAt.Before(*next)) {
			next = r.ExpiresAt
		}
	}
	if next == nil {
		return
	}
	e.stopExpiry = e.AfterFunc(next.Sub(now)+time.Second, func() {
		if _, err := e.Reconcile(context.Background(), nil); err != nil {
			log.Printf("firewall: reconcile after expiry failed: %v", err)
		}
	})
}

// desired turns stored state plus host facts into the engine model.
// Entries that cannot be expressed are returned as warnings and skipped.
func (e *Engine) desired(ctx context.Context, st State) (nft.Ruleset, HostInfo, []error, error) {
	host, err := e.Detect()
	if err != nil {
		return nft.Ruleset{}, host, nil, fmt.Errorf("host detection failed: %w", err)
	}
	rs, warnings, err := BuildRuleset(ctx, e.Store, host.SSHPorts, host.Egress)
	if err != nil {
		return rs, host, warnings, err
	}
	now := e.Now()

	for _, s := range st.Services {
		svc := nft.Service{ID: s.ID, Proto: nft.Protocol(s.Protocol),
			Ports: nft.PortRange{From: uint16(s.PortFrom), To: uint16(s.PortTo)}, Interface: s.Interface}
		ok := true
		for _, src := range s.Sources {
			p, err := parsePrefix(src)
			if err != nil {
				warnings = append(warnings, fmt.Errorf("service %s: %v", s.ID, err))
				ok = false
				break
			}
			svc.Sources = append(svc.Sources, p)
		}
		if !ok {
			continue
		}
		if err := validEntry(rs, func(p *nft.Ruleset) { p.Services = []nft.Service{svc} }); err != nil {
			warnings = append(warnings, err)
			continue
		}
		rs.Services = append(rs.Services, svc)
	}

	for _, r := range st.IPRules {
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		p, err := parsePrefix(r.Prefix)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("IP rule %s: %v", r.ID, err))
			continue
		}
		if r.Action == "block" && r.Ports == "" {
			rs.Blocked = append(rs.Blocked, nft.BlockedEntry{Prefix: p, Expires: r.ExpiresAt})
			continue
		}
		rule := nft.IPRule{ID: r.ID, Prefix: p, Action: r.Action, Proto: nft.Protocol(r.Protocol)}
		if r.Ports != "" {
			if rule.Ports, err = ParsePorts(r.Ports); err != nil {
				warnings = append(warnings, fmt.Errorf("IP rule %s: %v", r.ID, err))
				continue
			}
		}
		if err := validEntry(rs, func(p *nft.Ruleset) { p.IPRules = []nft.IPRule{rule} }); err != nil {
			warnings = append(warnings, err)
			continue
		}
		rs.IPRules = append(rs.IPRules, rule)
	}

	for _, f := range st.Forwards {
		ip, err := netip.ParseAddr(f.TargetIP)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("forward %s: %v", f.ID, err))
			continue
		}
		fwd := nft.PortForward{ID: f.ID, Proto: nft.Protocol(f.Protocol),
			PublicPort: uint16(f.PublicPort), TargetIP: ip.Unmap(), TargetPort: uint16(f.TargetPort)}
		if err := validEntry(rs, func(p *nft.Ruleset) { p.Forwards = []nft.PortForward{fwd} }); err != nil {
			warnings = append(warnings, err)
			continue
		}
		rs.Forwards = append(rs.Forwards, fwd)
	}

	for _, id := range st.EgressNodeIDs {
		node, err := e.Store.GetNode(ctx, id)
		if err != nil || node == nil {
			warnings = append(warnings, fmt.Errorf("egress node %s not found", id))
			continue
		}
		addr, ok := netip.AddrFromSlice(node.VirtualIP)
		if !ok || !addr.Unmap().Is4() {
			warnings = append(warnings, fmt.Errorf("egress node %s has no IPv4 address", id))
			continue
		}
		rs.Egress = append(rs.Egress, addr.Unmap())
	}
	return rs, host, warnings, nil
}

// validEntry checks one stored entry against the base ruleset (SSH ports,
// egress, networks), so a single invalid row, e.g. an imported rule on a
// reserved admin port, is skipped with a warning instead of blocking every
// change.
func validEntry(base nft.Ruleset, add func(*nft.Ruleset)) error {
	probe := nft.Ruleset{SSHPorts: base.SSHPorts, EgressInterface: base.EgressInterface, Networks: base.Networks}
	add(&probe)
	return nft.Validate(probe)
}

// parsePrefix accepts "a.b.c.d", "a.b.c.d/n" and IPv6 forms, unmapping
// IPv4-mapped addresses.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() {
			return ipv4Prefix(p)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ImportStore is what the one-time iptables import reads and writes.
type ImportStore interface {
	GetFirewallMeta(ctx context.Context, key string) (string, bool, error)
	ImportFirewallRules(ctx context.Context, services []*models.FirewallService, rules []*models.FirewallIPRule, metaKey, metaValue string) error
}

// ImportedKey marks that panel-made iptables rules were imported once.
const ImportedKey = "iptables_imported"

// ImportIptables copies panel-made INPUT rules from iptables into the engine's
// tables once (in one transaction), so switching to nft mode keeps opened
// ports and blocks. r must read the host's iptables (use nft.NsenterRunner).
func ImportIptables(ctx context.Context, st ImportStore, r nft.Runner, sshPorts []uint16, now time.Time) (int, []string, error) {
	if _, done, err := st.GetFirewallMeta(ctx, ImportedKey); err != nil || done {
		return 0, nil, err
	}
	out, err := r.Run("", "iptables", "-S", "INPUT")
	if err != nil {
		return 0, nil, fmt.Errorf("read iptables rules: %w", err)
	}
	services, ipRules, skipped := ParseIptablesInput(out, sshPorts)
	if err := st.ImportFirewallRules(ctx, services, ipRules, ImportedKey, now.UTC().Format(time.RFC3339)); err != nil {
		return 0, skipped, fmt.Errorf("import iptables rules: %w", err)
	}
	return len(services) + len(ipRules), skipped, nil
}
```
`iptables_import.go`:
```go
package firewall

import (
	"net/netip"
	"strings"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// ParseIptablesInput converts the panel-made rules in `iptables -S INPUT`
// output into engine records. Installer rules (interface-bound, conntrack,
// loopback, ICMP, the WireGuard range, SSH ports, unsourced DROPs) and chains
// owned by other tools (fail2ban) are skipped and returned for logging.
func ParseIptablesInput(out string, sshPorts []uint16) ([]*models.FirewallService, []*models.FirewallIPRule, []string) {
	var services []*models.FirewallService
	var ipRules []*models.FirewallIPRule
	var skipped []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		r := parseIptablesRule(line)
		switch {
		case r.iface != "" || r.module == "state" || r.module == "conntrack" || r.proto == "icmp":
			skipped = append(skipped, line)
		case r.target != "ACCEPT" && r.target != "DROP":
			skipped = append(skipped, line) // e.g. -j f2b-sshd, -j REJECT
		case r.proto == "udp" && r.source == "" && inWireGuardRange(r.ports):
			skipped = append(skipped, line) // installer or reset WireGuard range
		case r.target == "DROP" && r.source == "":
			skipped = append(skipped, line) // installer safety-net drops
		case r.target == "ACCEPT" && r.source == "" && r.ports == "":
			skipped = append(skipped, line)
		case r.target == "ACCEPT" && r.ports != "" && (r.proto == "tcp" || r.proto == "udp"):
			if r.source == "" && r.proto == "tcp" && isSSHOnly(r.ports, sshPorts) {
				skipped = append(skipped, line)
				continue
			}
			for _, pr := range strings.Split(r.ports, ",") {
				from, to := splitRange(pr)
				svc := &models.FirewallService{Protocol: r.proto, Sources: []string{}, Comment: "imported from iptables"}
				svc.PortFrom, svc.PortTo = from, to
				if r.source != "" {
					svc.Sources = []string{r.source}
				}
				if svc.PortFrom > 0 {
					services = append(services, svc)
				}
			}
		case r.source != "":
			action := "allow"
			if r.target == "DROP" {
				action = "block"
			}
			rule := &models.FirewallIPRule{Action: action, Prefix: r.source, Origin: "import", Comment: "imported from iptables"}
			if r.ports != "" && (r.proto == "tcp" || r.proto == "udp") {
				rule.Protocol, rule.Ports = r.proto, r.ports
			}
			ipRules = append(ipRules, rule)
		default:
			skipped = append(skipped, line)
		}
	}
	return services, ipRules, skipped
}

type iptablesRule struct {
	source, proto, ports, target, iface, module string
}

func parseIptablesRule(line string) iptablesRule {
	var r iptablesRule
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "-s":
			r.source = canonicalPrefix(f[i+1])
		case "-p":
			r.proto = f[i+1]
		case "--dport", "--dports":
			r.ports = strings.ReplaceAll(f[i+1], ":", "-")
		case "-j":
			r.target = f[i+1]
		case "-i":
			r.iface = f[i+1]
		case "-m":
			if f[i+1] == "state" || f[i+1] == "conntrack" {
				r.module = f[i+1]
			}
		}
	}
	return r
}

func canonicalPrefix(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return s
}

func splitRange(s string) (int, int) {
	ranges, err := ParsePorts(s)
	if err != nil || len(ranges) != 1 {
		return 0, 0
	}
	return int(ranges[0].From), int(ranges[0].To)
}

// inWireGuardRange reports whether every port lies in 51820-51900, the range
// setup-firewall.sh (51820:51900) and the legacy reset (51820:51830) open.
func inWireGuardRange(ports string) bool {
	ranges, err := ParsePorts(ports)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if r.From < 51820 || r.To > 51900 {
			return false
		}
	}
	return true
}

func isSSHOnly(ports string, sshPorts []uint16) bool {
	for _, p := range strings.Split(ports, ",") {
		from, to := splitRange(p)
		if from == 0 || from != to {
			return false
		}
		found := false
		for _, s := range sshPorts {
			if int(s) == from {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
```
`host.go`:
```go
package firewall

import (
	"fmt"
	"path"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

const (
	// PersistPath is the ruleset the boot unit loads before Docker starts.
	PersistPath = "/etc/novusgate/firewall.nft"
	// rollbackUnit and rollbackPath belong to the host-side rollback timer.
	rollbackUnit = "novusgate-fw-rollback"
	rollbackPath = "/var/lib/novusgate/fw-rollback.nft"
	// ConfirmTimeout is how long a confirmable change waits before rollback.
	ConfirmTimeout = 60 * time.Second
)

// NewHostEngine wires the engine to the real host. nft runs in the control
// plane's container (it shares the host's network namespace); the rollback
// timer, its script and the boot-time ruleset live on the host via nsenter.
func NewHostEngine(mode Mode, st Store) *Engine {
	host := nft.NsenterRunner{}
	applier := nft.NewSafeApplier(
		nft.Executor{Runner: nft.HostRunner{}},
		nft.SystemdTimer{Runner: host, Unit: rollbackUnit, Path: rollbackPath},
		ConfirmTimeout,
	)
	return &Engine{
		Mode:    mode,
		Store:   st,
		Applier: applier,
		Now:     time.Now,
		Detect: func() (HostInfo, error) {
			ports, egress, err := DetectHost(nft.HostRunner{})
			return HostInfo{SSHPorts: ports, Egress: egress}, err
		},
		Persist: func(script string) error { return WriteHostFile(host, PersistPath, script) },
		AfterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
	}
}

// WriteHostFile writes content to a host path through r (use nsenter).
func WriteHostFile(r nft.Runner, file, content string) error {
	if _, err := r.Run("", "mkdir", "-p", path.Dir(file)); err != nil {
		return fmt.Errorf("create %s: %w", path.Dir(file), err)
	}
	if _, err := r.Run(content, "tee", file); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	return nil
}
```

- [ ] **Step 4: GREEN.** Eyni əmr. Expected: 18 test PASS. Sonra `bash server/scripts/test-with-postgres.sh` işlət, hamısı `ok` olmalıdır.

- [ ] **Step 5: Commit**

```bash
git add server/internal/controlplane/firewall/
git commit -m "feat: add firewall engine with confirm-before-store, expiry and iptables import"
```

---

### Task 4: REST: v2 API, nft rejimində v1 adapterləri, startup

**Files:**
- Create: `server/internal/controlplane/api/rest/firewall_engine.go`
- Create: `server/internal/controlplane/api/rest/firewall_v2_handlers.go`
- Create: `server/internal/controlplane/api/rest/firewall_v1_nft.go`
- Create: `server/internal/controlplane/api/rest/firewall_engine_test.go`
- Modify: `handlers.go`, `firewall_handlers.go`, `cmd/control-plane/main.go`, `deployments/docker/docker-compose.yml` (yalnız aşağıda göstərilən əlavələr)

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `(*Server).SetFirewall`, `engineEnforces`, `StartFirewall`, `reconcileFirewall`, `protectAddrs`;
  - routes `/api/v1/firewall/v2/{state,preview,services,ip-rules,forwards,egress/{nodeId},confirm/{id}}`.

- [ ] **Step 1: Uğursuz testi yaz** (`firewall_engine_test.go`)

```go
package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// recRunner is a fake host: it records nft scripts instead of loading them.
type recRunner struct {
	mu      sync.Mutex
	applied []string
}

func (r *recRunner) Run(stdin, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := strings.Join(append([]string{name}, args...), " ")
	switch cmd {
	case "nft -f -":
		r.applied = append(r.applied, stdin)
	case "nft list table inet novusgate":
		return "table inet novusgate {\n}\n", nil
	}
	return "", nil
}

func (r *recRunner) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return ""
	}
	return r.applied[len(r.applied)-1]
}

type recTimer struct{ active bool }

func (t *recTimer) Arm(string, time.Duration) error { t.active = true; return nil }
func (t *recTimer) Disarm() error                   { t.active = false; return nil }
func (t *recTimer) Active() (bool, error)           { return t.active, nil }

// newEngineServer builds a Server on TEST_DATABASE_URL with an engine whose
// host is faked. The firewall tables are emptied first.
func newEngineServer(t *testing.T, mode firewall.Mode) (*Server, *recRunner) {
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
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetFirewallHostRules(ctx); err != nil {
		t.Fatal(err)
	}
	forwards, _ := st.ListFirewallForwards(ctx)
	for _, f := range forwards {
		st.DeleteFirewallForward(ctx, f.ID)
	}

	r := &recRunner{}
	applier := &nft.SafeApplier{
		Exec: nft.Executor{Runner: r}, Timer: &recTimer{}, Timeout: time.Minute, Grace: 15 * time.Second,
		Now:       time.Now,
		AfterFunc: func(time.Duration, func()) func() bool { return func() bool { return true } },
	}
	s := &Server{store: st, router: mux.NewRouter(), managers: map[string]*wireguard.Manager{},
		peerActivity: map[string]*PeerActivity{}}
	s.setupRoutes()
	s.SetFirewall(&firewall.Engine{
		Mode: mode, Store: st, Applier: applier, Now: time.Now,
		Detect: func() (firewall.HostInfo, error) {
			return firewall.HostInfo{SSHPorts: []uint16{22}, Egress: "eth0"}, nil
		},
		Persist: func(string) error { return nil },
	})
	return s, r
}

func call(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.200:5555" // the operator
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func inputRules(t *testing.T, s *Server) FirewallStatus {
	t.Helper()
	rec := call(t, s, "GET", "/api/v1/firewall/host/rules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET rules = %d %s", rec.Code, rec.Body)
	}
	var st FirewallStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func findRule(st FirewallStatus, proto, port string) (FirewallRule, bool) {
	for _, c := range st.Chains {
		for _, r := range c.Rules {
			if r.Protocol == proto && r.Port == port {
				return r, true
			}
		}
	}
	return FirewallRule{}, false
}

func TestLegacyPortEndpointsInNftMode(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)

	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/open", `{"port":443,"protocol":"both"}`); rec.Code != 200 {
		t.Fatalf("open = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(r.last(), "tcp dport 443 accept") || !strings.Contains(r.last(), "udp dport 443 accept") {
		t.Fatalf("both protocols must be applied:\n%s", r.last())
	}
	st := inputRules(t, s)
	if _, ok := findRule(st, "tcp", "443"); !ok {
		t.Fatal("the legacy view must list the opened port")
	}
	if ssh, ok := findRule(st, "tcp", "22"); !ok || !ssh.Protected || ssh.Number != 1 {
		t.Fatalf("SSH must be listed first and protected: %+v", ssh)
	}

	rec := call(t, s, "POST", "/api/v1/firewall/host/port/close", `{"port":443,"protocol":"tcp"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rules_deleted":1`) {
		t.Fatalf("close = %d %s", rec.Code, rec.Body)
	}
	udp, _ := findRule(inputRules(t, s), "udp", "443")
	body := `{"chain":"INPUT","line_number":` + itoa(udp.Number) + `}`
	if rec := call(t, s, "POST", "/api/v1/firewall/host/rules/delete", body); rec.Code != 200 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, ok := findRule(inputRules(t, s), "udp", "443"); ok {
		t.Fatal("the deleted rule must be gone")
	}

	if rec := call(t, s, "POST", "/api/v1/firewall/host/rules/delete", `{"chain":"INPUT","line_number":1,"force":true}`); rec.Code != http.StatusForbidden {
		t.Fatalf("deleting the SSH rule must be forbidden even with force, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/close", `{"port":22,"protocol":"tcp"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("closing SSH without force must be forbidden, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/import", `{"rules":"*filter\nCOMMIT\n"}`); rec.Code != http.StatusConflict {
		t.Fatalf("iptables import must be refused in nft mode, got %d", rec.Code)
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/host/export", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "table inet novusgate") {
		t.Fatalf("export = %d %s", rec.Code, rec.Body)
	}
}

func TestLegacyIPEndpointsAndPermanentBansInNftMode(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)

	for _, body := range []string{`{"ip":"203.0.113.7","ports":"80,443"}`, `{"ip":"198.51.100.9"}`} {
		if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", body); rec.Code != 200 {
			t.Fatalf("block %s = %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/allow", `{"ip":"192.0.2.0/24"}`); rec.Code != 200 {
		t.Fatalf("allow = %d %s", rec.Code, rec.Body)
	}
	script := r.last()
	for _, want := range []string{"ip saddr 203.0.113.7 tcp dport { 80, 443 } counter drop", "elements = { 198.51.100.9 }", "ip saddr 192.0.2.0/24 accept"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in\n%s", want, script)
		}
	}
	if st := inputRules(t, s); st.BlockedIPs != 2 {
		t.Fatalf("blocked_ips = %d, want 2", st.BlockedIPs)
	}

	// Blocking the network the operator comes from must be refused.
	if rec := call(t, s, "POST", "/api/v1/firewall/host/ip/block", `{"ip":"198.51.100.0/24"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-block = %d %s", rec.Code, rec.Body)
	}

	if rec := call(t, s, "POST", "/api/v1/system/fail2ban/ban", `{"jail":"sshd","ip":"203.0.113.99","permanent":true}`); rec.Code != 200 {
		t.Fatalf("permanent ban = %d %s", rec.Code, rec.Body)
	}
	rec := call(t, s, "GET", "/api/v1/system/fail2ban/permanent-bans", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"count":2`) || !strings.Contains(rec.Body.String(), `"ip":"203.0.113.99"`) {
		t.Fatalf("permanent bans = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "DELETE", "/api/v1/system/fail2ban/permanent-bans", `{"ip":"203.0.113.99"}`); rec.Code != 200 {
		t.Fatalf("unban = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "GET", "/api/v1/system/fail2ban/permanent-bans", ""); !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Fatalf("after unban: %s", rec.Body)
	}

	if rec := call(t, s, "POST", "/api/v1/firewall/host/reset", ""); rec.Code != 200 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if st := inputRules(t, s); st.BlockedIPs != 0 {
		t.Fatal("reset must remove panel blocks")
	}
}

func TestV2ChangesWaitForConfirmation(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeNft)
	ctx := context.Background()
	net := &models.Network{Name: "fw-rest-test", CIDR: "10.20.0.0/24", InterfaceName: "wg91", ListenPort: 51991}
	if err := s.store.CreateNetwork(ctx, net); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.DeleteNetwork(context.Background(), net.ID) })

	rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`)
	var resp struct {
		Pending *struct{ ID string } `json:"pending"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Pending == nil {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(r.last(), "tcp dport 9443 accept") {
		t.Fatal("the change must be live while it waits for confirmation")
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/v2/state", ""); !strings.Contains(rec.Body.String(), `"services":[]`) {
		t.Fatalf("nothing may be stored before confirmation: %s", rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/host/port/open", `{"port":80,"protocol":"tcp"}`); rec.Code != http.StatusConflict {
		t.Fatalf("other changes must wait while one is pending, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/confirm/"+resp.Pending.ID, ""); rec.Code != 200 {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/v2/state", ""); !strings.Contains(rec.Body.String(), `"port_from":9443`) {
		t.Fatalf("confirmed change must be stored: %s", rec.Body)
	}

	rec = call(t, s, "POST", "/api/v1/firewall/v2/forwards?confirm=false",
		`{"protocol":"tcp","public_port":8081,"target_ip":"10.20.0.5","target_port":80}`)
	if rec.Code != 200 || !strings.Contains(r.last(), "dnat ip to 10.20.0.5:80") {
		t.Fatalf("forward = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/forwards?confirm=false",
		`{"protocol":"tcp","public_port":22,"target_ip":"10.20.0.5","target_port":22}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a forward on the SSH port must be rejected, got %d", rec.Code)
	}
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"sctp","port_from":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid input must be 400, got %d", rec.Code)
	}
}

func TestV2DisabledOutsideNftMode(t *testing.T) {
	s, r := newEngineServer(t, firewall.ModeShadow)
	if rec := call(t, s, "POST", "/api/v1/firewall/v2/services", `{"protocol":"tcp","port_from":9443}`); rec.Code != http.StatusConflict {
		t.Fatalf("v2 changes in shadow mode = %d, want 409", rec.Code)
	}
	if rec := call(t, s, "GET", "/api/v1/firewall/v2/preview", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "table inet novusgate") {
		t.Fatalf("preview works in every mode: %d %s", rec.Code, rec.Body)
	}
	if len(r.applied) != 0 {
		t.Fatal("nothing may be applied outside nft mode")
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
```

- [ ] **Step 2: RED.** `bash server/scripts/test-with-postgres.sh`. Expected: build FAIL, `s.SetFirewall undefined`.

- [ ] **Step 3: Yeni fayllar**

`firewall_engine.go`:
```go
package rest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// errNotFound is returned by engine mutations that reference a missing record.
var errNotFound = errors.New("not found")

// SetFirewall attaches the nftables engine. Without it, or in iptables mode,
// the legacy iptables code paths are used everywhere.
func (s *Server) SetFirewall(e *firewall.Engine) {
	s.firewall = e
}

// engineEnforces reports whether nftables (not iptables) enforces the host firewall.
func (s *Server) engineEnforces() bool {
	return s.firewall != nil && s.firewall.Mode == firewall.ModeNft
}

// StartFirewall prepares the engine at startup: shadow mode validates the
// ruleset; nft mode imports panel-made iptables rules once, removes the
// legacy VPN rules from iptables and applies the stored state.
func (s *Server) StartFirewall(ctx context.Context) error {
	if s.firewall == nil {
		return nil
	}
	switch s.firewall.Mode {
	case firewall.ModeShadow:
		warnings, err := s.firewall.Check(ctx)
		logWarnings(warnings)
		if err != nil {
			return fmt.Errorf("shadow check failed: %w", err)
		}
		fmt.Println("[Firewall] shadow mode: nftables ruleset compiles and passes nft -c")
	case firewall.ModeNft:
		host, err := s.firewall.Detect()
		if err != nil {
			return err
		}
		n, skipped, err := firewall.ImportIptables(ctx, s.store, nft.NsenterRunner{}, host.SSHPorts, time.Now())
		if err != nil {
			return err
		}
		if n > 0 || len(skipped) > 0 {
			fmt.Printf("[Firewall] imported %d panel rules from iptables (%d installer/foreign rules left alone)\n", n, len(skipped))
		}
		if err := s.clearNovusGateVPNRules(); err != nil {
			fmt.Printf("[Firewall] warning: could not remove legacy iptables VPN rules: %v\n", err)
		}
		res, err := s.firewall.Reconcile(ctx, nil)
		logWarnings(res.Warnings)
		if err != nil {
			return fmt.Errorf("initial apply failed: %w", err)
		}
		fmt.Println("[Firewall] nftables engine applied the stored ruleset")
	}
	return nil
}

// reconcileFirewall re-applies the stored state after a change that affects
// the ruleset (networks, nodes, VPN rules). Errors are logged, not returned:
// the triggering request already succeeded.
func (s *Server) reconcileFirewall(ctx context.Context) {
	if !s.engineEnforces() {
		return
	}
	res, err := s.firewall.Reconcile(ctx, nil)
	logWarnings(res.Warnings)
	if err != nil {
		fmt.Printf("[Firewall] reconcile failed: %v\n", err)
	}
}

func logWarnings(warnings []error) {
	for _, w := range warnings {
		fmt.Printf("[Firewall] warning: %v\n", w)
	}
}

// protectAddrs returns the addresses the request comes from, plus the public
// WireGuard endpoint of that peer when it arrives over the VPN, so a change
// can never cut off the operator making it.
func (s *Server) protectAddrs(r *http.Request) []netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	remote = remote.Unmap()
	addrs := []netip.Addr{remote}
	if ep, ok := s.wireGuardEndpointFor(remote); ok {
		addrs = append(addrs, ep)
	}
	return addrs
}

// wireGuardEndpointFor finds the public endpoint of the peer that owns addr.
func (s *Server) wireGuardEndpointFor(addr netip.Addr) (netip.Addr, bool) {
	s.managersMu.RLock()
	defer s.managersMu.RUnlock()
	for _, mgr := range s.managers {
		peers, err := mgr.GetPeers()
		if err != nil {
			continue
		}
		for _, p := range peers {
			for _, allowed := range strings.Split(p.AllowedIPs, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(allowed))
				if err != nil || !prefix.Contains(addr) {
					continue
				}
				ap, err := netip.ParseAddrPort(p.Endpoint)
				if err != nil {
					continue
				}
				return ap.Addr().Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}

// engineError writes the HTTP status that matches an engine error.
func engineError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotFound):
		errorResponse(w, http.StatusNotFound, err.Error())
	case errors.Is(err, firewall.ErrEngineDisabled),
		errors.Is(err, nft.ErrPendingConfirmation),
		errors.Is(err, nft.ErrRollbackArmed):
		errorResponse(w, http.StatusConflict, err.Error())
	case errors.Is(err, firewall.ErrRejected):
		errorResponse(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, nft.ErrExpired), errors.Is(err, nft.ErrNoPending):
		errorResponse(w, http.StatusGone, err.Error())
	default:
		errorResponse(w, http.StatusInternalServerError, err.Error())
	}
}

func warningStrings(warnings []error) []string {
	out := make([]string, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, w.Error())
	}
	return out
}

// canonicalPrefix turns "a.b.c.d", "a.b.c.d/n" or IPv6 forms into a masked
// CIDR string, unmapping IPv4-mapped addresses.
func canonicalPrefix(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return "", fmt.Errorf("invalid CIDR %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}
```
`firewall_v2_handlers.go`:
```go
package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// /api/v1/firewall/v2/* manages the nftables engine. Mutations wait for
// confirmation (POST .../confirm/{id}) unless called with ?confirm=false.

func (s *Server) setupFirewallV2Routes(api *mux.Router) {
	api.HandleFunc("/firewall/v2/state", s.handleFirewallV2State).Methods("GET")
	api.HandleFunc("/firewall/v2/preview", s.handleFirewallV2Preview).Methods("GET")
	api.HandleFunc("/firewall/v2/services", s.handleFirewallV2CreateService).Methods("POST")
	api.HandleFunc("/firewall/v2/services/{id}", s.handleFirewallV2DeleteService).Methods("DELETE")
	api.HandleFunc("/firewall/v2/ip-rules", s.handleFirewallV2CreateIPRule).Methods("POST")
	api.HandleFunc("/firewall/v2/ip-rules/{id}", s.handleFirewallV2DeleteIPRule).Methods("DELETE")
	api.HandleFunc("/firewall/v2/forwards", s.handleFirewallV2CreateForward).Methods("POST")
	api.HandleFunc("/firewall/v2/forwards/{id}", s.handleFirewallV2DeleteForward).Methods("DELETE")
	api.HandleFunc("/firewall/v2/egress/{nodeId}", s.handleFirewallV2SetEgress).Methods("PUT", "DELETE")
	api.HandleFunc("/firewall/v2/confirm/{id}", s.handleFirewallV2Confirm).Methods("POST")
}

func (s *Server) handleFirewallV2State(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	resp := map[string]interface{}{
		"mode":            s.firewall.Mode,
		"services":        st.Services,
		"ip_rules":        st.IPRules,
		"forwards":        st.Forwards,
		"egress_node_ids": st.EgressNodeIDs,
		"pending":         nil,
	}
	if p, ok := s.firewall.PendingChange(); ok {
		resp["pending"] = map[string]interface{}{"id": p.ID, "deadline": p.Deadline}
	}
	if host, err := s.firewall.Detect(); err != nil {
		resp["host_error"] = err.Error()
	} else {
		resp["ssh_ports"] = host.SSHPorts
		resp["egress_interface"] = host.Egress
	}
	jsonResponse(w, http.StatusOK, resp)
}

func (s *Server) handleFirewallV2Preview(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	script, warnings, err := s.firewall.Preview(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"script": script, "warnings": warningStrings(warnings)})
}

// proposeV2 runs a change and writes the common response.
func (s *Server) proposeV2(w http.ResponseWriter, r *http.Request, item interface{}, ch firewall.Change) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	confirm := r.URL.Query().Get("confirm") != "false"
	res, err := s.firewall.Propose(r.Context(), ch, confirm, s.protectAddrs(r))
	if err != nil {
		engineError(w, err)
		return
	}
	var pending interface{}
	if res.Pending != nil {
		pending = map[string]interface{}{"id": res.Pending.ID, "deadline": res.Pending.Deadline}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"item":     item,
		"pending":  pending,
		"warnings": warningStrings(res.Warnings),
	})
}

type v2ServiceRequest struct {
	Protocol  string   `json:"protocol"`
	PortFrom  int      `json:"port_from"`
	PortTo    int      `json:"port_to"`
	Sources   []string `json:"sources"`
	Interface string   `json:"interface"`
	Comment   string   `json:"comment"`
}

func (s *Server) handleFirewallV2CreateService(w http.ResponseWriter, r *http.Request) {
	var req v2ServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	svc, err := validateService(req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	s.proposeV2(w, r, svc, addServices(s, svc))
}

func validateService(req v2ServiceRequest) (*models.FirewallService, error) {
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		return nil, fmt.Errorf("protocol must be tcp or udp")
	}
	if req.PortTo == 0 {
		req.PortTo = req.PortFrom
	}
	if req.PortFrom < 1 || req.PortTo > 65535 || req.PortTo < req.PortFrom {
		return nil, fmt.Errorf("invalid port range %d-%d", req.PortFrom, req.PortTo)
	}
	if req.Interface != "" && !nft.ValidInterfaceName(req.Interface) {
		return nil, fmt.Errorf("invalid interface %q", req.Interface)
	}
	sources := []string{}
	for _, src := range req.Sources {
		p, err := canonicalPrefix(src)
		if err != nil {
			return nil, err
		}
		sources = append(sources, p)
	}
	return &models.FirewallService{ID: uuid.New().String(), Protocol: req.Protocol, PortFrom: req.PortFrom,
		PortTo: req.PortTo, Sources: sources, Interface: req.Interface, Comment: req.Comment}, nil
}

// addServices is the change that opens one or more services.
func addServices(s *Server, svcs ...*models.FirewallService) firewall.Change {
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.Services = append(st.Services, svcs...)
			return nil
		},
		Commit: func(ctx context.Context) error {
			for _, svc := range svcs {
				if err := s.store.CreateFirewallService(ctx, svc); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// removeServices is the change that deletes the services with the given IDs.
func removeServices(s *Server, ids ...string) firewall.Change {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			kept := st.Services[:0:0]
			found := 0
			for _, svc := range st.Services {
				if drop[svc.ID] {
					found++
					continue
				}
				kept = append(kept, svc)
			}
			if found != len(drop) {
				return fmt.Errorf("service %w", errNotFound)
			}
			st.Services = kept
			return nil
		},
		Commit: func(ctx context.Context) error {
			for id := range drop {
				if err := s.store.DeleteFirewallService(ctx, id); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (s *Server) handleFirewallV2DeleteService(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.proposeV2(w, r, map[string]string{"id": id}, removeServices(s, id))
}

type v2IPRuleRequest struct {
	Action    string     `json:"action"`
	Prefix    string     `json:"prefix"`
	Protocol  string     `json:"protocol"`
	Ports     string     `json:"ports"`
	ExpiresAt *time.Time `json:"expires_at"`
	Comment   string     `json:"comment"`
}

func (s *Server) handleFirewallV2CreateIPRule(w http.ResponseWriter, r *http.Request) {
	var req v2IPRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rule, err := validateIPRule(req, "panel", time.Now())
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	s.proposeV2(w, r, rule, addIPRule(s, rule))
}

func validateIPRule(req v2IPRuleRequest, origin string, now time.Time) (*models.FirewallIPRule, error) {
	if req.Action != "block" && req.Action != "allow" {
		return nil, fmt.Errorf("action must be block or allow")
	}
	prefix, err := canonicalPrefix(req.Prefix)
	if err != nil {
		return nil, err
	}
	if req.Protocol != "" && req.Protocol != "tcp" && req.Protocol != "udp" {
		return nil, fmt.Errorf("protocol must be tcp, udp or empty")
	}
	if req.Ports != "" {
		if req.Protocol == "" {
			req.Protocol = "tcp" // the legacy panel blocked and allowed TCP ports
		}
		if _, err := firewall.ParsePorts(req.Ports); err != nil {
			return nil, err
		}
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}
	return &models.FirewallIPRule{ID: uuid.New().String(), Action: req.Action, Prefix: prefix, Protocol: req.Protocol,
		Ports: req.Ports, ExpiresAt: req.ExpiresAt, Origin: origin, Comment: req.Comment}, nil
}

func addIPRule(s *Server, rule *models.FirewallIPRule) firewall.Change {
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.IPRules = append(st.IPRules, rule)
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.CreateFirewallIPRule(ctx, rule) },
	}
}

// removeIPRules is the change that deletes the IP rules with the given IDs.
func removeIPRules(s *Server, ids ...string) firewall.Change {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			kept := st.IPRules[:0:0]
			found := 0
			for _, rule := range st.IPRules {
				if drop[rule.ID] {
					found++
					continue
				}
				kept = append(kept, rule)
			}
			if found != len(drop) {
				return fmt.Errorf("IP rule %w", errNotFound)
			}
			st.IPRules = kept
			return nil
		},
		Commit: func(ctx context.Context) error {
			for id := range drop {
				if err := s.store.DeleteFirewallIPRule(ctx, id); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (s *Server) handleFirewallV2DeleteIPRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.proposeV2(w, r, map[string]string{"id": id}, removeIPRules(s, id))
}

type v2ForwardRequest struct {
	Protocol   string `json:"protocol"`
	PublicPort int    `json:"public_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Comment    string `json:"comment"`
}

func (s *Server) handleFirewallV2CreateForward(w http.ResponseWriter, r *http.Request) {
	var req v2ForwardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		errorResponse(w, http.StatusBadRequest, "protocol must be tcp or udp")
		return
	}
	if req.PublicPort < 1 || req.PublicPort > 65535 || req.TargetPort < 1 || req.TargetPort > 65535 {
		errorResponse(w, http.StatusBadRequest, "ports must be 1-65535")
		return
	}
	ip, err := netip.ParseAddr(req.TargetIP)
	if err != nil || !ip.Unmap().Is4() {
		errorResponse(w, http.StatusBadRequest, "target_ip must be an IPv4 address of a VPN node")
		return
	}
	f := &models.FirewallForward{ID: uuid.New().String(), Protocol: req.Protocol, PublicPort: req.PublicPort,
		TargetIP: ip.Unmap().String(), TargetPort: req.TargetPort, Comment: req.Comment}
	s.proposeV2(w, r, f, firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.Forwards = append(st.Forwards, f)
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.CreateFirewallForward(ctx, f) },
	})
}

func (s *Server) handleFirewallV2DeleteForward(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.proposeV2(w, r, map[string]string{"id": id}, firewall.Change{
		Mutate: func(st *firewall.State) error {
			for i, f := range st.Forwards {
				if f.ID == id {
					st.Forwards = append(st.Forwards[:i:i], st.Forwards[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("forward %w", errNotFound)
		},
		Commit: func(ctx context.Context) error { return s.store.DeleteFirewallForward(ctx, id) },
	})
}

func (s *Server) handleFirewallV2SetEgress(w http.ResponseWriter, r *http.Request) {
	nodeID := mux.Vars(r)["nodeId"]
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil || node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	enable := r.Method == http.MethodPut
	s.proposeV2(w, r, map[string]interface{}{"node_id": nodeID, "egress": enable}, firewall.Change{
		Mutate: func(st *firewall.State) error {
			kept := st.EgressNodeIDs[:0:0]
			for _, id := range st.EgressNodeIDs {
				if id != nodeID {
					kept = append(kept, id)
				}
			}
			if enable {
				kept = append(kept, nodeID)
			}
			st.EgressNodeIDs = kept
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.SetNodeEgress(ctx, nodeID, enable) },
	})
}

func (s *Server) handleFirewallV2Confirm(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	if err := s.firewall.Confirm(r.Context(), mux.Vars(r)["id"]); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "confirmed"})
}
```
`firewall_v1_nft.go`:
```go
package rest

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Legacy (v1) firewall endpoints in nft mode. They keep the request and
// response shapes the existing panel uses, but read and write the engine's
// tables. They apply immediately (no confirmation UI exists for them); the
// lockout guard still protects every change.

// v1Entry is one synthesized INPUT rule with the record it came from.
type v1Entry struct {
	rule      FirewallRule
	serviceID string
	ipRuleID  string
}

// v1Entries lists the INPUT chain the legacy panel shows: structural rules
// managed by NovusGate (protected) first, then services and IP rules.
func (s *Server) v1Entries(ctx context.Context) ([]v1Entry, error) {
	host, err := s.firewall.Detect()
	if err != nil {
		return nil, err
	}
	st, err := s.firewall.LoadState(ctx)
	if err != nil {
		return nil, err
	}
	var out []v1Entry
	add := func(e v1Entry) {
		e.rule.Number = len(out) + 1
		e.rule.Chain = "INPUT"
		if e.rule.Source == "" {
			e.rule.Source = "anywhere"
		}
		e.rule.Destination = "anywhere"
		out = append(out, e)
	}
	for _, p := range host.SSHPorts {
		add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "tcp", Port: strconv.Itoa(int(p)), Options: "SSH", Protected: true}})
	}
	add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "udp", Port: "51820:51900", Options: "WireGuard", Protected: true}})
	for _, p := range nft.AdminPorts {
		add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "tcp", Port: strconv.Itoa(int(p)),
			Interface: nft.AdminInterface, InInterface: nft.AdminInterface, Options: "admin VPN only", Protected: true}})
	}
	for _, p := range nft.APIPorts {
		add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "tcp", Port: strconv.Itoa(int(p)),
			Interface: nft.VPNInterfacePattern, InInterface: nft.VPNInterfacePattern, Options: "VPN only", Protected: true}})
	}
	for _, svc := range st.Services {
		port := strconv.Itoa(svc.PortFrom)
		if svc.PortTo != svc.PortFrom {
			port = fmt.Sprintf("%d:%d", svc.PortFrom, svc.PortTo)
		}
		add(v1Entry{serviceID: svc.ID, rule: FirewallRule{Target: "ACCEPT", Protocol: svc.Protocol, Port: port,
			Source: strings.Join(svc.Sources, ","), Interface: svc.Interface, InInterface: svc.Interface, Options: svc.Comment}})
	}
	now := time.Now()
	for _, r := range st.IPRules {
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		target := "ACCEPT"
		if r.Action == "block" {
			target = "DROP"
		}
		proto := r.Protocol
		if proto == "" {
			proto = "all"
		}
		add(v1Entry{ipRuleID: r.ID, rule: FirewallRule{Target: target, Protocol: proto, Port: r.Ports,
			Source: strings.TrimSuffix(r.Prefix, "/32"), Options: r.Comment}})
	}
	return out, nil
}

func (s *Server) handleFirewallGetRulesNft(w http.ResponseWriter, r *http.Request, chains []string) {
	entries, err := s.v1Entries(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	result := FirewallStatus{Chains: []ChainInfo{}}
	for _, name := range chains {
		chain := ChainInfo{Name: name, Policy: "ACCEPT", Rules: []FirewallRule{}}
		if name == "INPUT" {
			chain.Policy = "DROP"
			for _, e := range entries {
				chain.Rules = append(chain.Rules, e.rule)
				if e.rule.Target == "DROP" && e.rule.Source != "anywhere" {
					result.BlockedIPs++
				}
				if e.rule.Target == "ACCEPT" && e.rule.Port != "" {
					result.OpenPorts++
				}
			}
		}
		result.TotalRules += len(chain.Rules)
		result.Chains = append(result.Chains, chain)
	}
	jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handleFirewallOpenPortNft(w http.ResponseWriter, r *http.Request, req OpenPortRequest, protocols []string) {
	var sources []string
	if req.Source != "" {
		p, err := canonicalPrefix(req.Source)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid source IP/CIDR")
			return
		}
		sources = []string{p}
	}
	var svcs []*models.FirewallService
	for _, proto := range protocols {
		svcs = append(svcs, &models.FirewallService{ID: uuid.New().String(), Protocol: proto,
			PortFrom: req.Port, PortTo: req.Port, Sources: append([]string{}, sources...)})
	}
	if _, err := s.firewall.Propose(r.Context(), addServices(s, svcs...), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"message":  fmt.Sprintf("Port %d/%s opened successfully", req.Port, req.Protocol),
		"port":     req.Port,
		"protocol": req.Protocol,
		"source":   req.Source,
	})
}

func (s *Server) handleFirewallClosePortNft(w http.ResponseWriter, r *http.Request, req ClosePortRequest, protocols []string) {
	host, err := s.firewall.Detect()
	if err != nil {
		engineError(w, err)
		return
	}
	for _, p := range host.SSHPorts {
		if int(p) == req.Port && !req.Force {
			errorResponse(w, http.StatusForbidden, fmt.Sprintf("port %d (SSH) is protected. Set force=true to override", req.Port))
			return
		}
	}
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	var ids []string
	for _, svc := range st.Services {
		for _, proto := range protocols {
			if svc.Protocol == proto && svc.PortFrom == req.Port && svc.PortTo == req.Port {
				ids = append(ids, svc.ID)
			}
		}
	}
	if len(ids) > 0 {
		if _, err := s.firewall.Propose(r.Context(), removeServices(s, ids...), false, s.protectAddrs(r)); err != nil {
			engineError(w, err)
			return
		}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":        "success",
		"message":       fmt.Sprintf("Port %d/%s closed successfully", req.Port, req.Protocol),
		"port":          req.Port,
		"protocol":      req.Protocol,
		"rules_deleted": len(ids),
	})
}

// handleFirewallIPRuleNft implements legacy Block IP and Allow IP.
func (s *Server) handleFirewallIPRuleNft(w http.ResponseWriter, r *http.Request, action, ip, ports string) {
	rule, err := validateIPRule(v2IPRuleRequest{Action: action, Prefix: ip, Ports: ports}, "panel", time.Now())
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.firewall.Propose(r.Context(), addIPRule(s, rule), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	verb := "blocked"
	if action == "allow" {
		verb = "allowed"
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("IP %s %s successfully", ip, verb),
		"ip":      ip,
		"ports":   ports,
	})
}

func (s *Server) handleFirewallDeleteRuleNft(w http.ResponseWriter, r *http.Request, req DeleteRuleRequest) {
	if req.Chain != "INPUT" {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("rule %d not found in chain %s", req.LineNumber, req.Chain))
		return
	}
	entries, err := s.v1Entries(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	if req.LineNumber > len(entries) {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("rule %d not found in chain %s", req.LineNumber, req.Chain))
		return
	}
	e := entries[req.LineNumber-1]
	if e.rule.Protected {
		// Structural rules are part of every compiled ruleset; force cannot remove them.
		errorResponse(w, http.StatusForbidden, fmt.Sprintf("rule %d is protected (SSH/WireGuard/Admin) and managed by NovusGate", req.LineNumber))
		return
	}
	ch := removeServices(s, e.serviceID)
	if e.ipRuleID != "" {
		ch = removeIPRules(s, e.ipRuleID)
	}
	if _, err := s.firewall.Propose(r.Context(), ch, false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"message":      fmt.Sprintf("Rule %d deleted from chain %s", req.LineNumber, req.Chain),
		"chain":        req.Chain,
		"line_number":  req.LineNumber,
		"deleted_rule": e.rule,
	})
}

func (s *Server) handleFirewallExportNft(w http.ResponseWriter, r *http.Request) {
	out, err := s.firewall.Applier.Exec.Runner.Run("", "nft", "list", "table", "inet", nft.TableName)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to export rules: %v", err))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"novusgate-nftables.txt\"")
	w.Write([]byte(out))
}

func (s *Server) handleFirewallResetNft(w http.ResponseWriter, r *http.Request) {
	ch := firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.Services, st.IPRules = nil, nil
			return nil
		},
		Commit: s.store.ResetFirewallHostRules,
	}
	if _, err := s.firewall.Propose(r.Context(), ch, false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Firewall reset to default NovusGate configuration",
	})
}

// Fail2Ban permanent bans are whole-address blocks in the engine.

func (s *Server) handleFail2BanPermanentBanNft(w http.ResponseWriter, r *http.Request, ip string) {
	rule, err := validateIPRule(v2IPRuleRequest{Action: "block", Prefix: ip}, "fail2ban", time.Now())
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.firewall.Propose(r.Context(), addIPRule(s, rule), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s permanently banned via nftables", ip),
		"type":    "permanent",
	})
}

// wholeBlocks returns whole-address blocks (the legacy "permanent bans").
func wholeBlocks(st firewall.State) []*models.FirewallIPRule {
	var out []*models.FirewallIPRule
	for _, r := range st.IPRules {
		if r.Action == "block" && r.Ports == "" && r.ExpiresAt == nil {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) handleFail2BanGetPermanentBansNft(w http.ResponseWriter, r *http.Request) {
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	bans := []map[string]interface{}{}
	for i, rule := range wholeBlocks(st) {
		bans = append(bans, map[string]interface{}{
			"line_number": strconv.Itoa(i + 1),
			"ip":          strings.TrimSuffix(rule.Prefix, "/32"),
			"target":      "DROP",
			"protocol":    "all",
		})
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"permanent_bans": bans, "count": len(bans)})
}

func (s *Server) handleFail2BanRemovePermanentBanNft(w http.ResponseWriter, r *http.Request, ip string) {
	prefix, err := canonicalPrefix(ip)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	var ids []string
	for _, rule := range wholeBlocks(st) {
		if rule.Prefix == prefix {
			ids = append(ids, rule.ID)
		}
	}
	if len(ids) == 0 {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("no permanent ban for %s", ip))
		return
	}
	if _, err := s.firewall.Propose(r.Context(), removeIPRules(s, ids...), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Permanent ban removed for IP %s", ip),
	})
}
```

- [ ] **Step 4: `handlers.go`-ya əlavələr** (yalnız bunlar)

1. Import blokunda `".../controlplane/store"` sətrindən əvvəl:
```go
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
```
2. `type Server struct`-da `peerActivity map[string]*PeerActivity` sətrindən sonra:
```go
	firewall     *firewall.Engine // nil, or engine for FIREWALL_ENGINE=shadow|nft
```
3. `setupRoutes`-da `api.HandleFunc("/firewall/vpn/apply", ...)` sətrindən sonra:
```go
	s.setupFirewallV2Routes(api)
```
4. `handleCreateNetwork`-da `jsonResponse(w, http.StatusCreated, network)`-dan əvvəl, `handleDeleteNetwork`-da `w.WriteHeader(http.StatusNoContent)`-dan əvvəl, `handleDeleteNode`-da `jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})`-dan əvvəl:
```go
	s.reconcileFirewall(r.Context())
```
5. `handleFail2BanManualBan`-da `if req.Permanent {` sətrindən dərhal sonra:
```go
		if s.engineEnforces() {
			s.handleFail2BanPermanentBanNft(w, r, req.IP)
			return
		}
```
6. `handleFail2BanGetPermanentBans`-ın əvvəlində (`// Get iptables rules that DROP traffic` şərhindən əvvəl):
```go
	if s.engineEnforces() {
		s.handleFail2BanGetPermanentBansNft(w, r)
		return
	}
```
7. `handleFail2BanRemovePermanentBan`-da `// Remove the DROP rule for this IP` şərhindən əvvəl:
```go
	if s.engineEnforces() {
		s.handleFail2BanRemovePermanentBanNft(w, r, req.IP)
		return
	}
```

- [ ] **Step 5: `firewall_handlers.go`-ya budaqlar** (validasiyadan sonra, iptables-dən əvvəl)

| Handler | Lövbər (anchor) — bu sətirdən **əvvəl** əlavə et | Əlavə |
|---|---|---|
| `handleFirewallGetRules` | `result := FirewallStatus{` | `if s.engineEnforces() { s.handleFirewallGetRulesNft(w, r, chains); return }` |
| `handleFirewallOpenPort` | `for _, proto := range protocols {` | `if s.engineEnforces() { s.handleFirewallOpenPortNft(w, r, req, protocols); return }` |
| `handleFirewallClosePort` | `deletedCount := 0` | `if s.engineEnforces() { s.handleFirewallClosePortNft(w, r, req, protocols); return }` |
| `handleFirewallBlockIP` | `// Build iptables command` | `if s.engineEnforces() { s.handleFirewallIPRuleNft(w, r, "block", req.IP, req.Ports); return }` |
| `handleFirewallAllowIP` | `// Build iptables command` | `if s.engineEnforces() { s.handleFirewallIPRuleNft(w, r, "allow", req.IP, req.Ports); return }` |
| `handleFirewallDeleteRule` | `// Get current rules to check if protected` | `if s.engineEnforces() { s.handleFirewallDeleteRuleNft(w, r, req); return }` |

Funksiyanın ilk sətri kimi əlavə et:
- `handleFirewallExport`: `if s.engineEnforces() { s.handleFirewallExportNft(w, r); return }`
- `handleFirewallImport`: `if s.engineEnforces() { errorResponse(w, http.StatusConflict, "importing iptables rules is not supported while the nftables engine enforces the firewall"); return }`
- `handleFirewallReset`: `if s.engineEnforces() { s.handleFirewallResetNft(w, r); return }`
- `syncVPNFirewallRules`:
```go
	if s.engineEnforces() {
		// The engine enforces VPN rules in table inet novusgate.
		if _, err := execHostCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			fmt.Printf("[Firewall] warning: enable ip_forward: %v\n", err)
		}
		_, err := s.firewall.Reconcile(ctx, nil)
		return err
	}
```
(Bloklar multi-line Go şəklində yazılır, cədvəldə qısaldılıb.)

- [ ] **Step 6: `main.go` və compose**

`main.go`-nun import blokuna `".../controlplane/firewall"` əlavə et. `apiServer := rest.NewServer(db)` sətrindən sonra:
```go
	// Firewall engine: iptables (default, legacy paths), shadow (check only) or nft.
	fwMode, err := firewall.ParseMode(os.Getenv("FIREWALL_ENGINE"))
	if err != nil {
		return err
	}
	if fwMode != firewall.ModeIptables {
		apiServer.SetFirewall(firewall.NewHostEngine(fwMode, db))
		go func() {
			if err := apiServer.StartFirewall(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "[Firewall] startup failed: %v\n", err)
			}
		}()
		fmt.Printf("  Firewall engine: %s\n", fwMode)
	}
```
`docker-compose.yml`-da control-plane xidmətinin `ADMIN_CIDR` sətrindən sonra:
```yaml
      # Firewall engine: iptables (default) | shadow (check only) | nft (enforce)
      FIREWALL_ENGINE: ${FIREWALL_ENGINE:-iptables}
```

- [ ] **Step 7: GREEN.** `bash server/scripts/test-with-postgres.sh`. Expected: `ok` `…/api/rest`, `…/firewall`, `…/store`, `…/nft`; REST testləri real DB-də keçir. `gofmt -l` yalnız yeni fayllarda yoxlanılır.

- [ ] **Step 8: Commit**

```bash
git add server/
git commit -m "feat: wire nftables engine into the API behind FIREWALL_ENGINE"
```

---

### Task 5: Sənədlər və staging runbook

**Files:**
- Create: `docs/runbooks/p3b1-firewall-engine.md`
- Modify: `docs/active-context.md`, `docs/architecture.md`, `docs/api.md` (yoxdursa, yarat)

- [ ] **Step 1: `docs/api.md`-yə v2 endpoint-lərini yaz.** Hər endpoint üçün method, path, body, cavab və status kodları göstərilir:
  - `409`: engine söndürülüb, təsdiq gözləyən dəyişiklik var, ya da rollback timer qurulub;
  - `400`: dəyişiklik rədd edilib (lockout və ya validasiya);
  - `410`: dəyişikliyin müddəti bitib.

- [ ] **Step 2: Runbook** (`docs/runbooks/p3b1-firewall-engine.md`). Staging VM-də bu ardıcıllıqla:
  1. `FIREWALL_ENGINE=shadow` ilə `docker compose up -d`. Log-da `shadow mode: nftables ruleset compiles` görünməlidir.
  2. `apt-get install -y nftables` (host). Sonra `FIREWALL_ENGINE=nft`. Log-da `imported N panel rules` və `applied the stored ruleset` görünməlidir.
  3. `nft list table inet novusgate`. SSH portları, açılmış portlar və bloklar orada olmalıdır.
  4. Panel → Open Port 8444 → `nft list chain inet novusgate input | grep 8444`.
  5. v2 təsdiqli dəyişiklik → 60 saniyə gözlə → avtomatik rollback olmalıdır (`systemctl list-timers novusgate-fw-rollback*`).
  6. v2 dəyişiklik → `POST /confirm/{id}`. Dəyişiklik qalmalıdır və `/etc/novusgate/firewall.nft` yenilənməlidir.
  7. Öz IP-ni bloklamağa cəhd et → 400 almalısan.
  8. `FIREWALL_ENGINE=iptables`-ə qayıt. Köhnə davranış bərpa olunmalıdır.

  **Qeyd:** iptables-in `INPUT DROP` siyasəti P3b-2 keçidinə qədər qalır. Ona görə nft-də açılan yeni portlar iptables tərəfindən hələ də bloklana bilər. Bu, P3b-2-nin işidir.

- [ ] **Step 3: `active-context.md` və `architecture.md`-ni yenilə, commit et**

```bash
git add docs/
git commit -m "docs: document firewall engine API and P3b-1 staging runbook"
```
