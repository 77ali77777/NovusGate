package quota

import (
	"context"
	"fmt"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/traffic"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Store is what the tracker reads and writes.
type Store interface {
	ListLimitProfiles(ctx context.Context) ([]models.LimitProfile, error)
	ListNodeLimits(ctx context.Context) ([]models.NodeLimit, error)
	ListQuotaStates(ctx context.Context) ([]models.NodeQuotaState, error)
	// SaveQuotaStateIf writes st only if the stored row is still the one read
	// (prev is its updated_at, nil when there was none); false otherwise.
	SaveQuotaStateIf(ctx context.Context, st models.NodeQuotaState, prev *time.Time) (bool, error)
	DeleteQuotaState(ctx context.Context, nodeID string) error
	GetNode(ctx context.Context, id string) (*models.Node, error)
}

// Tracker counts every sample of a node with a quota and acts on the
// thresholds. It runs after each traffic sample (every 5 minutes).
type Tracker struct {
	Store Store
	Now   func() time.Time
	// Apply re-applies the firewall when a node becomes blocked or free.
	Apply func()
	// Notify sends a notification; key deduplicates it.
	Notify func(key, text string)
	// Enforcing reports whether the firewall applies quotas (nft mode).
	Enforcing func() bool
}

func toState(m models.NodeQuotaState) State {
	return State{NodeID: m.NodeID, PeriodStart: m.PeriodStart, PeriodEnd: m.PeriodEnd, UsedBytes: m.UsedBytes, LastRx: m.LastRx,
		LastTx: m.LastTx, HasLast: true, WarnedAt: m.WarnedAt, ExceededAt: m.ExceededAt}
}

func toModel(s State) models.NodeQuotaState {
	return models.NodeQuotaState{NodeID: s.NodeID, PeriodStart: s.PeriodStart, PeriodEnd: s.PeriodEnd, UsedBytes: s.UsedBytes,
		LastRx: s.LastRx, LastTx: s.LastTx, WarnedAt: s.WarnedAt, ExceededAt: s.ExceededAt}
}

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

func same(a, b State) bool {
	return a.PeriodStart.Equal(b.PeriodStart) && a.PeriodEnd.Equal(b.PeriodEnd) && a.UsedBytes == b.UsedBytes && a.LastRx == b.LastRx &&
		a.LastTx == b.LastTx && a.HasLast == b.HasLast && sameTime(a.WarnedAt, b.WarnedAt) && sameTime(a.ExceededAt, b.ExceededAt)
}

// profileQuota turns a limit profile into its quota; ok is false without one.
func profileQuota(p models.LimitProfile) (Profile, bool) {
	if p.QuotaMB == nil {
		return Profile{}, false
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		return Profile{}, false
	}
	day := p.QuotaResetDay
	if day < 1 {
		day = 1
	}
	return Profile{QuotaBytes: int64(*p.QuotaMB) * 1_000_000, ResetDay: day, Loc: loc}, true
}

// Observe adds samples (possibly none) to the counts of nodes with a quota,
// starts new periods, and notifies and re-applies the firewall as needed.
func (t *Tracker) Observe(ctx context.Context, samples []traffic.Sample) error {
	profiles, err := t.Store.ListLimitProfiles(ctx)
	if err != nil {
		return err
	}
	nodeLimits, err := t.Store.ListNodeLimits(ctx)
	if err != nil {
		return err
	}
	stored, err := t.Store.ListQuotaStates(ctx)
	if err != nil {
		return err
	}
	byID := map[string]models.LimitProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	states := map[string]models.NodeQuotaState{}
	for _, st := range stored {
		states[st.NodeID] = st
	}
	latest := map[string]traffic.Sample{}
	for _, s := range samples {
		latest[s.NodeID] = s
	}
	now := t.Now()
	apply := false
	tracked := map[string]bool{}
	for _, nl := range nodeLimits {
		profile := byID[nl.ProfileID]
		q, ok := profileQuota(profile)
		if !ok {
			continue
		}
		tracked[nl.NodeID] = true
		m, has := states[nl.NodeID]
		before := State{NodeID: nl.NodeID}
		if has {
			before = toState(m)
		}
		var after State
		var events []Event
		if s, ok := latest[nl.NodeID]; ok {
			after, events = Advance(before, q, s.Rx, s.Tx, now)
		} else if has {
			after, events = Rollover(before, q, now)
		} else {
			continue
		}
		if !has || !same(before, after) {
			var prev *time.Time
			if has {
				prev = &m.UpdatedAt
			}
			saved, err := t.Store.SaveQuotaStateIf(ctx, toModel(after), prev)
			if err != nil {
				return err
			}
			if !saved {
				// Changed since it was read (a reset): the next run counts
				// from the stored row, and nothing here is acted on.
				continue
			}
		}
		for _, e := range events {
			switch e {
			case Exceeded, Lifted:
				apply = true
			}
			if e == Warned || e == Exceeded {
				t.notify(ctx, nl.NodeID, profile, q, after, e)
			}
		}
	}
	// A node without a quota keeps no count: an old baseline would count
	// the traffic it moved meanwhile, if a quota came back.
	for id := range states {
		if !tracked[id] {
			if err := t.Store.DeleteQuotaState(ctx, id); err != nil {
				return err
			}
			if states[id].ExceededAt != nil {
				apply = true
			}
		}
	}
	if apply && t.Apply != nil {
		t.Apply()
	}
	return nil
}

func gigabytes(b int64) string { return fmt.Sprintf("%.1f GB", float64(b)/1e9) }

func (t *Tracker) notify(ctx context.Context, nodeID string, p models.LimitProfile, q Profile, st State, e Event) {
	if t.Notify == nil {
		return
	}
	name := nodeID
	if n, err := t.Store.GetNode(ctx, nodeID); err == nil && n != nil {
		name = n.Name
	}
	// The mark's time keeps a repeat after a reset or a raised quota apart.
	at := st.ExceededAt
	if e == Warned {
		at = st.WarnedAt
	}
	key := fmt.Sprintf("%s:%s:%s", nodeID, e, at.UTC().Format(time.RFC3339Nano))
	var text string
	if e == Warned {
		text = fmt.Sprintf("NovusGate: %s used %d%% of its monthly traffic quota (%s of %s).",
			name, WarnPercent, gigabytes(st.UsedBytes), gigabytes(q.QuotaBytes))
	} else {
		action := "blocked"
		if p.QuotaAction == "throttle" {
			action = "throttled"
		}
		text = fmt.Sprintf("NovusGate: %s used its monthly traffic quota (%s); its VPN traffic is %s until %s.",
			name, gigabytes(q.QuotaBytes), action, st.PeriodEnd.In(q.Loc).Format("2006-01-02"))
		if t.Enforcing != nil && !t.Enforcing() {
			text += " The firewall runs in iptables mode and does not enforce quotas."
		}
	}
	t.Notify(key, text)
}
