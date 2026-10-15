package store

import (
	"context"
	"errors"
	"testing"

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
	if err := s.SetLimitProfileBindings(ctx, p2.ID, []string{a.ID, "00000000-0000-0000-0000-000000000000"}, nil); err == nil {
		t.Fatal("unknown node: want an error")
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
