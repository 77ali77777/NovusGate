// Package reconciler keeps WireGuard peers equal to the database: active
// nodes are peers, inactive ones are not. In shadow mode it only reports the
// difference; in enforce mode it applies it. Expired nodes are marked and
// their peers removed in both modes (the lazy expiry of the panel, on time).
package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
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
	Actions []Action // applied (enforce; expired-peer removals in both modes)
	Pending []Action // shadow: adds and updates enforce would make
	Unknown []string
	// Duplicates lists public keys shared by several nodes of one network.
	Duplicates []string
	Errors     []string
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
	done    chan struct{} // closed when Run returns

	// logged holds the findings already logged, so a finding that stays
	// the same is logged once instead of on every tick.
	logged map[string]bool
}

// New returns a reconciler; Run starts its loop.
func New(mode Mode, st Store, peers func(string) PeerControl) *Reconciler {
	return &Reconciler{Mode: mode, Store: st, Peers: peers, Now: time.Now, trigger: make(chan struct{}, 1),
		done: make(chan struct{}), logged: map[string]bool{}}
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

	// Expire step (shadow and enforce): mark expired nodes in the database.
	// Their peers are removed by the diff step below, after a re-check, and
	// a failed removal is retried on the next run.
	expired, err := r.Store.ExpireNodes(ctx, now)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("expire nodes: %v", err))
	}
	for _, n := range expired {
		rep.Expired = append(rep.Expired, n.Name)
		slog.Info("reconciler: node expired", "node", n.Name, "interface", ifaces[n.NetworkID])
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
		actions, unknown, duplicates := plan(nw, nodes, live, now)
		sort.Strings(unknown)
		rep.Unknown = append(rep.Unknown, unknown...)
		rep.Duplicates = append(rep.Duplicates, duplicates...)
		plans = append(plans, planned{pc, actions})
	}

	seen := map[string]bool{}
	logOnce := func(key string, log func()) {
		seen[key] = true
		if !r.logged[key] {
			log()
		}
	}

	if r.beforeApply != nil {
		r.beforeApply()
	}
	for _, p := range plans {
		for _, a := range p.actions {
			// Removals only ever target inactive (expired) nodes: they run in
			// shadow too, as the panel's expiry always did. Adds and updates
			// wait for enforce.
			if r.Mode != ModeEnforce && a.Kind != "remove" {
				logOnce("pending "+a.Kind+" "+a.PublicKey+" "+a.AllowedIPs, func() {
					slog.Info("reconciler (shadow): would change peer", "kind", a.Kind, "node", a.Node, "interface", a.Interface, "allowed_ips", a.AllowedIPs)
				})
				rep.Pending = append(rep.Pending, a)
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
		logOnce("unknown "+u, func() { slog.Warn("reconciler: peer not in the database (left alone)", "peer", u) })
	}
	for _, d := range rep.Duplicates {
		logOnce("duplicate "+d, func() { slog.Warn("reconciler: nodes share a public key (peer kept while one is active)", "detail", d) })
	}
	r.logged = seen // a finding that went away is logged again if it returns
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

// Run reconciles every interval and whenever Trigger is called, until ctx
// is cancelled. The first run happens after one interval (or a trigger), so
// startup (loadNetworks bringing interfaces up and adopting peers) goes first.
func (r *Reconciler) Run(ctx context.Context, every time.Duration) {
	defer close(r.done)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.trigger:
		}
		r.safeRunOnce(ctx)
	}
}

// safeRunOnce runs RunOnce and turns a panic into a logged error, so one bad
// run does not stop the loop (or the process).
func (r *Reconciler) safeRunOnce(ctx context.Context) {
	defer func() {
		if v := recover(); v != nil {
			slog.Error("reconciler: run panicked", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
		}
	}()
	r.RunOnce(ctx)
}

// Wait blocks until Run has returned (after its context is cancelled and any
// run in progress has finished).
func (r *Reconciler) Wait() {
	<-r.done
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
