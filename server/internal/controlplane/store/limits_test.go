package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestLimitProfiles(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, a, b := groupFixture(t, s)
	s.db.ExecContext(ctx, "UPDATE nodes SET limit_profile_id = NULL")
	s.db.ExecContext(ctx, "UPDATE node_groups SET limit_profile_id = NULL")
	s.db.ExecContext(ctx, "DELETE FROM limit_profiles")

	down, conns := 2000, 50
	p := &models.LimitProfile{Name: "office", DownKbps: &down, MaxConnections: &conns, Timezone: "Asia/Baku",
		Schedule: []models.ScheduleWindow{{Days: []int{1, 2, 3, 4, 5}, From: "08:00", To: "18:00"}}}
	if err := s.CreateLimitProfile(ctx, p); err != nil || p.ID == "" {
		t.Fatalf("create = %v", err)
	}
	if err := s.CreateLimitProfile(ctx, &models.LimitProfile{Name: "office", Timezone: "UTC"}); !errors.Is(err, ErrLimitNameTaken) {
		t.Fatalf("duplicate name = %v", err)
	}
	g := &models.NodeGroup{Name: "limited"}
	if err := s.CreateNodeGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLimitProfileBindings(ctx, p.ID, []string{a.ID}, []string{g.ID}); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListLimitProfiles(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	got := list[0]
	if got.Name != "office" || *got.DownKbps != 2000 || got.UpKbps != nil || *got.MaxConnections != 50 ||
		got.Timezone != "Asia/Baku" || len(got.Schedule) != 1 || got.Schedule[0].To != "18:00" {
		t.Fatalf("profile = %+v", got)
	}
	if len(got.NodeIDs) != 1 || got.NodeIDs[0] != a.ID || len(got.GroupIDs) != 1 || got.GroupIDs[0] != g.ID {
		t.Fatalf("bindings = %v %v", got.NodeIDs, got.GroupIDs)
	}

	// Rebinding replaces: a leaves, b joins; the group is unbound.
	if err := s.SetLimitProfileBindings(ctx, p.ID, []string{b.ID}, nil); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListLimitProfiles(ctx)
	if len(list[0].NodeIDs) != 1 || list[0].NodeIDs[0] != b.ID || len(list[0].GroupIDs) != 0 {
		t.Fatalf("after rebind = %v %v", list[0].NodeIDs, list[0].GroupIDs)
	}

	if err := s.DeleteLimitProfile(ctx, p.ID); !errors.Is(err, ErrLimitInUse) {
		t.Fatalf("delete while bound = %v", err)
	}
	up := 512
	p.Name, p.UpKbps, p.DownKbps, p.Schedule = "office-2", &up, nil, nil
	if err := s.UpdateLimitProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListLimitProfiles(ctx)
	if list[0].Name != "office-2" || *list[0].UpKbps != 512 || list[0].DownKbps != nil || len(list[0].Schedule) != 0 {
		t.Fatalf("after update = %+v", list[0])
	}
	s.SetLimitProfileBindings(ctx, p.ID, nil, nil)
	if err := s.DeleteLimitProfile(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteLimitProfile(ctx, p.ID); err == nil {
		t.Fatal("deleting a missing profile must fail")
	}
	// An unknown node fails the whole binding.
	p2 := &models.LimitProfile{Name: "p2", Timezone: "UTC"}
	s.CreateLimitProfile(ctx, p2)
	if err := s.SetLimitProfileBindings(ctx, p2.ID, []string{a.ID, "00000000-0000-0000-0000-000000000000"}, nil); !errors.Is(err, ErrLimitMemberNotFound) {
		t.Fatalf("unknown node = %v, want ErrLimitMemberNotFound", err)
	}
	list, _ = s.ListLimitProfiles(ctx)
	for _, l := range list {
		if len(l.NodeIDs) != 0 {
			t.Fatalf("a failed binding must change nothing: %+v", l)
		}
	}
}

// A node's own profile wins over its groups'; among groups the first by name
// with a profile counts; nodes without any profile are not listed.
func TestEffectiveNodeLimits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, a, b := groupFixture(t, s)
	s.db.ExecContext(ctx, "UPDATE nodes SET limit_profile_id = NULL")
	s.db.ExecContext(ctx, "UPDATE node_groups SET limit_profile_id = NULL")
	s.db.ExecContext(ctx, "DELETE FROM limit_profiles")
	own := &models.LimitProfile{Name: "own", Timezone: "UTC"}
	zeta := &models.LimitProfile{Name: "zeta", Timezone: "UTC"}
	alpha := &models.LimitProfile{Name: "alpha", Timezone: "UTC"}
	for _, p := range []*models.LimitProfile{own, zeta, alpha} {
		if err := s.CreateLimitProfile(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	gZ := &models.NodeGroup{Name: "z-group"}
	gA := &models.NodeGroup{Name: "a-group"}
	s.CreateNodeGroup(ctx, gZ)
	s.CreateNodeGroup(ctx, gA)
	s.SetNodeGroupMembers(ctx, gZ.ID, []string{a.ID, b.ID})
	s.SetNodeGroupMembers(ctx, gA.ID, []string{b.ID})
	s.SetLimitProfileBindings(ctx, own.ID, []string{a.ID}, nil)
	s.SetLimitProfileBindings(ctx, zeta.ID, nil, []string{gZ.ID})
	s.SetLimitProfileBindings(ctx, alpha.ID, nil, []string{gA.ID})

	got, err := s.ListNodeLimits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byNode := map[string]models.NodeLimit{}
	for _, l := range got {
		byNode[l.NodeID] = l
	}
	if l := byNode[a.ID]; l.ProfileID != own.ID || l.GroupID != "" || l.VirtualIP != "10.79.0.2" {
		t.Errorf("a = %+v, want its own profile", l)
	}
	if l := byNode[b.ID]; l.ProfileID != alpha.ID || l.GroupID != gA.ID {
		t.Errorf("b = %+v, want alpha through a-group", l)
	}
	if len(got) != 2 {
		t.Errorf("got %d nodes, want 2", len(got))
	}
}

// Quota settings (P9c) round-trip with the profile; quota states are saved,
// listed and reset per node, and go with their node.
func TestQuotaFieldsAndState(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, a, b := groupFixture(t, s)
	s.db.ExecContext(ctx, "UPDATE nodes SET limit_profile_id = NULL")
	s.db.ExecContext(ctx, "UPDATE node_groups SET limit_profile_id = NULL")
	s.db.ExecContext(ctx, "DELETE FROM limit_profiles")
	s.db.ExecContext(ctx, "DELETE FROM node_quota_state")

	q, throttle := 50000, 512
	p := &models.LimitProfile{Name: "quota", Timezone: "UTC", QuotaMB: &q, QuotaAction: "throttle",
		ThrottleKbps: &throttle, QuotaResetDay: 15}
	if err := s.CreateLimitProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListLimitProfiles(ctx)
	got := list[0]
	if got.QuotaMB == nil || *got.QuotaMB != 50000 || got.QuotaAction != "throttle" || *got.ThrottleKbps != 512 || got.QuotaResetDay != 15 {
		t.Fatalf("profile = %+v", got)
	}

	start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	exceeded := start.Add(48 * time.Hour)
	for _, st := range []models.NodeQuotaState{
		{NodeID: a.ID, PeriodStart: start, UsedBytes: 123, LastRx: 10, LastTx: 20, ExceededAt: &exceeded},
		{NodeID: b.ID, PeriodStart: start, UsedBytes: 7},
	} {
		if err := s.SaveQuotaState(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	// Saving again updates.
	if err := s.SaveQuotaState(ctx, models.NodeQuotaState{NodeID: b.ID, PeriodStart: start, UsedBytes: 9, LastRx: 1}); err != nil {
		t.Fatal(err)
	}
	states, err := s.ListQuotaStates(ctx)
	if err != nil || len(states) != 2 {
		t.Fatalf("states = %v %v", states, err)
	}
	byNode := map[string]models.NodeQuotaState{}
	for _, st := range states {
		byNode[st.NodeID] = st
	}
	if st := byNode[a.ID]; st.UsedBytes != 123 || st.LastTx != 20 || st.ExceededAt == nil || !st.ExceededAt.Equal(exceeded) || !st.PeriodStart.Equal(start) {
		t.Errorf("a = %+v", st)
	}
	if st := byNode[b.ID]; st.UsedBytes != 9 || st.LastRx != 1 || st.ExceededAt != nil {
		t.Errorf("b = %+v", st)
	}
	if err := s.ResetQuotaState(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	states, _ = s.ListQuotaStates(ctx)
	for _, st := range states {
		if st.NodeID == a.ID && (st.UsedBytes != 0 || st.ExceededAt != nil || st.WarnedAt != nil || st.LastTx != 20) {
			t.Errorf("after reset a = %+v", st)
		}
	}
	if err := s.ResetQuotaState(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("reset unknown = %v", err)
	}
}

// The tracker writes only if the row is still the one it read, so a reset
// in between is not undone; counts can be deleted.
func TestQuotaStateConditionalSaveAndDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, a, _ := groupFixture(t, s)
	s.db.ExecContext(ctx, "DELETE FROM node_quota_state")
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	ok, err := s.SaveQuotaStateIf(ctx, models.NodeQuotaState{NodeID: a.ID, PeriodStart: start, PeriodEnd: end, UsedBytes: 1}, nil)
	if err != nil || !ok {
		t.Fatalf("first save = %v %v", ok, err)
	}
	if ok, _ := s.SaveQuotaStateIf(ctx, models.NodeQuotaState{NodeID: a.ID, PeriodStart: start, PeriodEnd: end}, nil); ok {
		t.Fatal("a second insert without prev must be refused")
	}
	states, _ := s.ListQuotaStates(ctx)
	read := states[0]
	if !read.PeriodEnd.Equal(end) || read.UpdatedAt.IsZero() {
		t.Fatalf("read = %+v", read)
	}
	if err := s.ResetQuotaState(ctx, a.ID); err != nil { // a concurrent reset
		t.Fatal(err)
	}
	if ok, _ := s.SaveQuotaStateIf(ctx, models.NodeQuotaState{NodeID: a.ID, PeriodStart: start, PeriodEnd: end, UsedBytes: 50}, &read.UpdatedAt); ok {
		t.Fatal("a write based on a stale read must be refused")
	}
	states, _ = s.ListQuotaStates(ctx)
	if states[0].UsedBytes != 0 {
		t.Fatalf("the reset was undone: %+v", states[0])
	}
	if ok, err := s.SaveQuotaStateIf(ctx, models.NodeQuotaState{NodeID: a.ID, PeriodStart: start, PeriodEnd: end, UsedBytes: 7}, &states[0].UpdatedAt); !ok || err != nil {
		t.Fatalf("a fresh write = %v %v", ok, err)
	}
	if err := s.DeleteQuotaState(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if states, _ = s.ListQuotaStates(ctx); len(states) != 0 {
		t.Fatalf("after delete = %v", states)
	}
}
