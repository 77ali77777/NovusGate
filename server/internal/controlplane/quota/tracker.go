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
	SaveQuotaState(ctx context.Context, st models.NodeQuotaState) error
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
}

func toState(m models.NodeQuotaState) State {
	return State{NodeID: m.NodeID, PeriodStart: m.PeriodStart, UsedBytes: m.UsedBytes, LastRx: m.LastRx,
		LastTx: m.LastTx, HasLast: true, WarnedAt: m.WarnedAt, ExceededAt: m.ExceededAt}
}

func toModel(s State) models.NodeQuotaState {
	return models.NodeQuotaState{NodeID: s.NodeID, PeriodStart: s.PeriodStart, UsedBytes: s.UsedBytes,
		LastRx: s.LastRx, LastTx: s.LastTx, WarnedAt: s.WarnedAt, ExceededAt: s.ExceededAt}
}

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

func same(a, b State) bool {
	return a.PeriodStart.Equal(b.PeriodStart) && a.UsedBytes == b.UsedBytes && a.LastRx == b.LastRx &&
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
	for _, nl := range nodeLimits {
		profile := byID[nl.ProfileID]
		q, ok := profileQuota(profile)
		if !ok {
			continue
		}
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
			if err := t.Store.SaveQuotaState(ctx, toModel(after)); err != nil {
				return err
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
	key := fmt.Sprintf("%s:%s:%s", nodeID, st.PeriodStart.UTC().Format(time.RFC3339), e)
	var text string
	if e == Warned {
		text = fmt.Sprintf("NovusGate: %s used %d%% of its monthly traffic quota (%s of %s).",
			name, WarnPercent, gigabytes(st.UsedBytes), gigabytes(q.QuotaBytes))
	} else {
		action := "blocked"
		if p.QuotaAction == "throttle" {
			action = "throttled"
		}
		next := time.Date(st.PeriodStart.In(q.Loc).Year(), st.PeriodStart.In(q.Loc).Month()+1, q.ResetDay, 0, 0, 0, 0, q.Loc)
		text = fmt.Sprintf("NovusGate: %s used its monthly traffic quota (%s); its VPN traffic is %s until %s.",
			name, gigabytes(q.QuotaBytes), action, next.Format("2006-01-02"))
	}
	t.Notify(key, text)
}
