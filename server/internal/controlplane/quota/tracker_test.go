package quota

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/traffic"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type fakeStore struct {
	profiles []models.LimitProfile
	limits   []models.NodeLimit
	states   map[string]models.NodeQuotaState
	saves    int
	deleted  []string
	// beforeSave runs inside SaveQuotaStateIf, as a concurrent writer would.
	beforeSave func()
	clock      time.Time
}

func (f *fakeStore) ListLimitProfiles(context.Context) ([]models.LimitProfile, error) {
	return f.profiles, nil
}
func (f *fakeStore) ListNodeLimits(context.Context) ([]models.NodeLimit, error) { return f.limits, nil }
func (f *fakeStore) ListQuotaStates(context.Context) ([]models.NodeQuotaState, error) {
	out := []models.NodeQuotaState{}
	for _, st := range f.states {
		out = append(out, st)
	}
	return out, nil
}
func (f *fakeStore) SaveQuotaStateIf(_ context.Context, st models.NodeQuotaState, prev *time.Time) (bool, error) {
	if f.beforeSave != nil {
		f.beforeSave()
		f.beforeSave = nil
	}
	cur, has := f.states[st.NodeID]
	if has != (prev != nil) || (has && !cur.UpdatedAt.Equal(*prev)) {
		return false, nil // changed since it was read
	}
	f.saves++
	f.clock = f.clock.Add(time.Microsecond)
	st.UpdatedAt = f.clock
	f.states[st.NodeID] = st
	return true, nil
}
func (f *fakeStore) DeleteQuotaState(_ context.Context, nodeID string) error {
	f.deleted = append(f.deleted, nodeID)
	delete(f.states, nodeID)
	return nil
}
func (f *fakeStore) GetNode(_ context.Context, id string) (*models.Node, error) {
	return &models.Node{ID: id, Name: "laptop-" + id}, nil
}

type harness struct {
	t       *testing.T
	store   *fakeStore
	tracker *Tracker
	now     time.Time
	applied int
	notes   []string
}

func newHarness(t *testing.T) *harness {
	q := 10 // MB
	h := &harness{t: t, now: time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)}
	h.store = &fakeStore{
		profiles: []models.LimitProfile{
			{ID: "p", Name: "q", QuotaMB: &q, QuotaAction: "block", QuotaResetDay: 1, Timezone: "UTC"},
			{ID: "free", Name: "no quota", Timezone: "UTC"},
		},
		limits: []models.NodeLimit{
			{NodeID: "n1", ProfileID: "p"},
			{NodeID: "n2", ProfileID: "free"},
		},
		states: map[string]models.NodeQuotaState{},
	}
	h.tracker = &Tracker{
		Store:  h.store,
		Now:    func() time.Time { return h.now },
		Apply:  func() { h.applied++ },
		Notify: func(key, text string) { h.notes = append(h.notes, key+" "+text) },
	}
	return h
}

func (h *harness) sample(at time.Duration, rx int64) {
	h.t.Helper()
	h.now = h.now.Add(at)
	if err := h.tracker.Observe(context.Background(), []traffic.Sample{
		{NodeID: "n1", At: h.now, Rx: rx},
		{NodeID: "n2", At: h.now, Rx: rx},
	}); err != nil {
		h.t.Fatal(err)
	}
}

// Only nodes whose profile has a quota are counted; crossing 80% and 100%
// notifies once each, and exceeding re-applies the firewall.
func TestTrackerCountsWarnsAndBlocks(t *testing.T) {
	h := newHarness(t)
	h.sample(0, 0)
	h.sample(5*time.Minute, 8_000_000)
	if _, ok := h.store.states["n2"]; ok {
		t.Fatal("a profile without a quota is not counted")
	}
	if len(h.notes) != 1 || !strings.Contains(h.notes[0], "laptop-n1") || !strings.Contains(h.notes[0], "80%") {
		t.Fatalf("notes = %v", h.notes)
	}
	if h.applied != 0 {
		t.Fatal("a warning does not change the firewall")
	}
	h.sample(5*time.Minute, 10_000_000)
	if h.store.states["n1"].ExceededAt == nil || h.applied != 1 || len(h.notes) != 2 {
		t.Fatalf("exceeded: state %+v applied %d notes %v", h.store.states["n1"], h.applied, h.notes)
	}
	h.sample(5*time.Minute, 11_000_000)
	if h.applied != 1 || len(h.notes) != 2 {
		t.Fatal("nothing new past 100%")
	}
}

// At the period change the block is lifted even if the node sends nothing.
func TestTrackerLiftsAtNewPeriodWithoutSamples(t *testing.T) {
	h := newHarness(t)
	h.sample(0, 0)
	h.sample(5*time.Minute, 10_000_000)
	if h.applied != 1 {
		t.Fatal("must be blocked")
	}
	h.now = h.now.Add(2 * time.Hour) // November 1st
	if err := h.tracker.Observe(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	st := h.store.states["n1"]
	if st.ExceededAt != nil || st.UsedBytes != 0 || h.applied != 2 {
		t.Fatalf("after the period change: %+v applied %d", st, h.applied)
	}
}

// States are saved only when they change, so idle runs cost nothing.
func TestTrackerSavesOnlyChanges(t *testing.T) {
	h := newHarness(t)
	h.sample(0, 0)
	saves := h.store.saves
	if err := h.tracker.Observe(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if h.store.saves != saves {
		t.Fatalf("saves %d -> %d without a change", saves, h.store.saves)
	}
}

// A node without a quota keeps no count: an old baseline would count the
// traffic it moved meanwhile once a quota comes back.
func TestTrackerDropsCountsWithoutQuota(t *testing.T) {
	h := newHarness(t)
	h.store.states["n2"] = models.NodeQuotaState{NodeID: "n2", UsedBytes: 5}
	h.sample(0, 0)
	if _, ok := h.store.states["n2"]; ok || len(h.store.deleted) != 1 {
		t.Fatalf("n2 count must go: %v", h.store.deleted)
	}
}

// A reset (REST) that lands between the tracker's read and write wins: the
// tracker's write is refused and the next run starts from the reset.
func TestTrackerDoesNotUndoAConcurrentReset(t *testing.T) {
	h := newHarness(t)
	h.sample(0, 0)
	h.sample(5*time.Minute, 10_000_000) // exceeded
	h.store.beforeSave = func() {
		st := h.store.states["n1"]
		st.UsedBytes, st.ExceededAt, st.WarnedAt = 0, nil, nil
		h.store.clock = h.store.clock.Add(time.Microsecond)
		st.UpdatedAt = h.store.clock
		h.store.states["n1"] = st
	}
	h.sample(5*time.Minute, 10_500_000)
	if st := h.store.states["n1"]; st.UsedBytes != 0 || st.ExceededAt != nil {
		t.Fatalf("the reset was undone: %+v", st)
	}
}

// Raising the quota lifts the block on the next run, without traffic.
func TestTrackerLiftsWhenTheQuotaIsRaised(t *testing.T) {
	h := newHarness(t)
	h.sample(0, 0)
	h.sample(5*time.Minute, 10_000_000)
	q := 20
	h.store.profiles[0].QuotaMB = &q
	if err := h.tracker.Observe(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if st := h.store.states["n1"]; st.ExceededAt != nil || h.applied != 2 {
		t.Fatalf("raised quota: %+v applied %d", st, h.applied)
	}
}
