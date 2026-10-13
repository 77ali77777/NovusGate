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
