package firewall

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func w(day time.Weekday, from, to string) nft.TimeWindow {
	parse := func(s string) int {
		tm, _ := time.Parse("15:04", s)
		if s == "24:00" {
			return 86400
		}
		return tm.Hour()*3600 + tm.Minute()*60
	}
	return nft.TimeWindow{Day: day, From: parse(from), To: parse(to)}
}

// Baku is UTC+4 all year: office hours move four hours back, and an early
// window crosses back into the previous UTC day.
func TestUTCWindowsShiftAndSplit(t *testing.T) {
	baku := mustLoc(t, "Asia/Baku")
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) // a Wednesday
	got := UTCWindows([]models.ScheduleWindow{
		{Days: []int{1}, From: "08:00", To: "18:00"},
		{Days: []int{3}, From: "02:00", To: "06:00"},
	}, baku, now)
	want := []nft.TimeWindow{
		w(time.Monday, "04:00", "14:00"),
		w(time.Tuesday, "22:00", "24:00"),
		w(time.Wednesday, "00:00", "02:00"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// A window that ends before it starts runs past midnight; "24:00" is the end
// of the day.
func TestUTCWindowsOvernightAndEndOfDay(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	got := UTCWindows([]models.ScheduleWindow{
		{Days: []int{6}, From: "22:00", To: "02:00"}, // Saturday night into Sunday
		{Days: []int{2}, From: "18:00", To: "24:00"},
	}, time.UTC, now)
	want := []nft.TimeWindow{
		w(time.Sunday, "00:00", "02:00"),
		w(time.Tuesday, "18:00", "24:00"),
		w(time.Saturday, "22:00", "24:00"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// Each weekday uses its own date's offset: New York switches to summer time
// on Sunday 2026-03-08, so Saturday is UTC-5 and Monday UTC-4.
func TestUTCWindowsAcrossDST(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	now := time.Date(2026, 3, 6, 15, 0, 0, 0, time.UTC) // Friday
	got := UTCWindows([]models.ScheduleWindow{{Days: []int{1, 6}, From: "09:00", To: "17:00"}}, ny, now)
	want := []nft.TimeWindow{
		w(time.Monday, "13:00", "21:00"),
		w(time.Saturday, "14:00", "22:00"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestNextOffsetChange(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	now := time.Date(2026, 3, 6, 15, 0, 0, 0, time.UTC)
	got, ok := NextOffsetChange(ny, now)
	want := time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC) // 02:00 EST
	if !ok || !got.Equal(want) {
		t.Fatalf("got %v %v, want %v", got, ok, want)
	}
	if _, ok := NextOffsetChange(time.UTC, now); ok {
		t.Fatal("UTC never changes")
	}
	if _, ok := NextOffsetChange(mustLoc(t, "Asia/Baku"), now); ok {
		t.Fatal("Baku has no DST")
	}
}

func intp(i int) *int { return &i }

func TestValidateLimitProfile(t *testing.T) {
	ok := models.LimitProfile{Name: "office", DownKbps: intp(1000), Timezone: "Asia/Baku",
		Schedule: []models.ScheduleWindow{{Days: []int{1, 5}, From: "08:00", To: "24:00"}}}
	if err := ValidateLimitProfile(ok); err != nil {
		t.Fatalf("valid profile: %v", err)
	}
	bad := map[string]func(p *models.LimitProfile){
		"empty name":      func(p *models.LimitProfile) { p.Name = " " },
		"zero speed":      func(p *models.LimitProfile) { p.DownKbps = intp(0) },
		"huge speed":      func(p *models.LimitProfile) { p.UpKbps = intp(100_000_001) },
		"zero conns":      func(p *models.LimitProfile) { p.MaxConnections = intp(0) },
		"unknown zone":    func(p *models.LimitProfile) { p.Timezone = "Mars/Olympus" },
		"empty zone":      func(p *models.LimitProfile) { p.Timezone = "" },
		"no days":         func(p *models.LimitProfile) { p.Schedule[0].Days = nil },
		"day 7":           func(p *models.LimitProfile) { p.Schedule[0].Days = []int{7} },
		"repeated day":    func(p *models.LimitProfile) { p.Schedule[0].Days = []int{1, 1} },
		"bad time":        func(p *models.LimitProfile) { p.Schedule[0].From = "25:00" },
		"short time":      func(p *models.LimitProfile) { p.Schedule[0].From = "8:00" },
		"start at 24":     func(p *models.LimitProfile) { p.Schedule[0].From = "24:00" },
		"empty window":    func(p *models.LimitProfile) { p.Schedule[0].To = "08:00" },
		"nothing to do":   func(p *models.LimitProfile) { p.DownKbps, p.Schedule = nil, nil },
		"too many window": func(p *models.LimitProfile) { p.Schedule = make([]models.ScheduleWindow, 50) },
	}
	for name, mutate := range bad {
		p := ok
		p.Schedule = append([]models.ScheduleWindow(nil), ok.Schedule...)
		mutate(&p)
		if err := ValidateLimitProfile(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// Profiles become nft limits named by profile ID order; speeds go from
// kbit/s to bytes/s; profiles nobody is bound to are left out.
func TestLimitsFromModels(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	profiles := []models.LimitProfile{
		{ID: "b-profile", SetNo: 2, Name: "guests", DownKbps: intp(8000), MaxConnections: intp(20), Timezone: "UTC",
			Schedule: []models.ScheduleWindow{{Days: []int{1}, From: "08:00", To: "18:00"}}},
		{ID: "a-profile", SetNo: 1, Name: "office", UpKbps: intp(1000), Timezone: "UTC"},
		{ID: "c-unused", Name: "unused", UpKbps: intp(1), Timezone: "UTC"},
	}
	nodes := []models.NodeLimit{
		{NodeID: "n1", VirtualIP: "10.20.0.5", ProfileID: "b-profile"},
		{NodeID: "n2", VirtualIP: "10.20.0.6", ProfileID: "b-profile"},
		{NodeID: "n3", VirtualIP: "10.30.0.2", ProfileID: "a-profile"},
		{NodeID: "n4", VirtualIP: "not-an-ip", ProfileID: "a-profile"},
	}
	got, warnings := LimitsFromModels(profiles, nodes, now)
	if len(warnings) != 1 {
		t.Errorf("warnings = %v, want one for the bad address", warnings)
	}
	want := []nft.Limit{
		{Name: "lim_1", ID: "a-profile", Members: []netip.Addr{netip.MustParseAddr("10.30.0.2")}, UpBytes: 125000},
		{Name: "lim_2", ID: "b-profile", Members: []netip.Addr{netip.MustParseAddr("10.20.0.5"), netip.MustParseAddr("10.20.0.6")},
			DownBytes: 1000000, MaxConns: 20, Windows: []nft.TimeWindow{w(time.Monday, "08:00", "18:00")}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// A window that started yesterday and runs past midnight uses yesterday's
// offset. Berlin leaves summer time on Sunday 2026-10-25; on Monday the 19th
// at 03:00 CEST the Sunday 22:00-06:00 window that is running must end at
// 04:00 UTC (06:00 CEST), not at 05:00 (06:00 CET of the 25th).
func TestUTCWindowsRunningOvernightUsesYesterday(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	now := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	got := UTCWindows([]models.ScheduleWindow{{Days: []int{0}, From: "22:00", To: "06:00"}}, berlin, now)
	want := []nft.TimeWindow{
		w(time.Sunday, "20:00", "24:00"),
		w(time.Monday, "00:00", "04:00"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// Over the quota (P9c) a node is blocked, or moved to a throttled copy of
// its profile; a count from an earlier period no longer applies.
func TestApplyQuotas(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	q, throttle := 1000, 256
	profiles := []models.LimitProfile{
		{ID: "block-p", SetNo: 1, Name: "b", QuotaMB: &q, QuotaAction: "block", QuotaResetDay: 1, Timezone: "UTC"},
		{ID: "slow-p", SetNo: 2, Name: "s", QuotaMB: &q, QuotaAction: "throttle", ThrottleKbps: &throttle, QuotaResetDay: 1,
			MaxConnections: intp(9), DownKbps: intp(128), Timezone: "UTC"},
	}
	nodes := []models.NodeLimit{
		{NodeID: "n1", VirtualIP: "10.1.0.1", ProfileID: "block-p"},
		{NodeID: "n2", VirtualIP: "10.1.0.2", ProfileID: "slow-p"},
		{NodeID: "n3", VirtualIP: "10.1.0.3", ProfileID: "slow-p"},
		{NodeID: "n4", VirtualIP: "10.1.0.4", ProfileID: "block-p"},
		{NodeID: "n5", VirtualIP: "10.1.0.5", ProfileID: "block-p"},
	}
	period := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	over := now.Add(-time.Hour)
	states := []models.NodeQuotaState{
		{NodeID: "n1", PeriodStart: period, PeriodEnd: end, UsedBytes: 2e9, ExceededAt: &over},
		{NodeID: "n2", PeriodStart: period, PeriodEnd: end, UsedBytes: 2e9, ExceededAt: &over},
		{NodeID: "n3", PeriodStart: period, PeriodEnd: end, UsedBytes: 1}, // under quota
		// last period: ended, whatever it says
		{NodeID: "n4", PeriodStart: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), PeriodEnd: period, UsedBytes: 2e9, ExceededAt: &over},
		// marked, but the quota was raised above the use since
		{NodeID: "n5", PeriodStart: period, PeriodEnd: end, UsedBytes: 5e8, ExceededAt: &over},
	}
	limits, _ := LimitsFromModels(profiles, nodes, now)
	limits, blocked := ApplyQuotas(limits, profiles, nodes, states, now)
	if len(blocked) != 1 || blocked[0].String() != "10.1.0.1" {
		t.Fatalf("blocked = %v", blocked)
	}
	var slow, throttled *nft.Limit
	for i := range limits {
		switch limits[i].ID {
		case "slow-p":
			slow = &limits[i]
		case "slow-p:quota":
			throttled = &limits[i]
		}
	}
	if slow == nil || throttled == nil {
		t.Fatalf("limits = %+v", limits)
	}
	if len(slow.Members) != 1 || slow.Members[0].String() != "10.1.0.3" {
		t.Errorf("slow members = %v, want only n3", slow.Members)
	}
	if len(throttled.Members) != 1 || throttled.Members[0].String() != "10.1.0.2" ||
		throttled.UpBytes != 32000 || throttled.DownBytes != 16000 || throttled.MaxConns != 9 || throttled.Name != "lim_2q" {
		t.Errorf("throttled = %+v", throttled)
	}
}

func TestValidateQuota(t *testing.T) {
	q := 1000
	ok := models.LimitProfile{Name: "q", Timezone: "UTC", QuotaMB: &q, QuotaAction: "block", QuotaResetDay: 5}
	if err := ValidateLimitProfile(ok); err != nil {
		t.Fatalf("a quota-only profile is valid: %v", err)
	}
	bad := map[string]func(p *models.LimitProfile){
		"zero quota":         func(p *models.LimitProfile) { p.QuotaMB = intp(0) },
		"unknown action":     func(p *models.LimitProfile) { p.QuotaAction = "delete" },
		"throttle no rate":   func(p *models.LimitProfile) { p.QuotaAction = "throttle" },
		"reset day 29":       func(p *models.LimitProfile) { p.QuotaResetDay = 29 },
		"reset day negative": func(p *models.LimitProfile) { p.QuotaResetDay = -1 },
		"zero throttle":      func(p *models.LimitProfile) { p.QuotaAction, p.ThrottleKbps = "throttle", intp(0) },
	}
	for name, mutate := range bad {
		p := ok
		mutate(&p)
		if err := ValidateLimitProfile(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// Set names follow the stored set numbers (P9 follow-up): a new group or
// profile never renames the sets of existing ones, so History diffs stay
// quiet.
func TestSetNamesAreStable(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	q, throttle := 1000, 256
	profiles := []models.LimitProfile{
		{ID: "b", SetNo: 7, UpKbps: intp(1000), Timezone: "UTC", QuotaMB: &q, QuotaAction: "throttle", ThrottleKbps: &throttle},
		{ID: "a", SetNo: 3, UpKbps: intp(1000), Timezone: "UTC"},
	}
	nodes := []models.NodeLimit{
		{NodeID: "n1", VirtualIP: "10.1.0.1", ProfileID: "b"},
		{NodeID: "n2", VirtualIP: "10.1.0.2", ProfileID: "a"},
		{NodeID: "n3", VirtualIP: "10.1.0.3", ProfileID: "b"},
	}
	limits, _ := LimitsFromModels(profiles, nodes, now)
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	limits, _ = ApplyQuotas(limits, profiles, nodes,
		[]models.NodeQuotaState{{NodeID: "n1", PeriodEnd: end, UsedBytes: 2e9}}, now)
	names := map[string]string{}
	for _, l := range limits {
		names[l.ID] = l.Name
	}
	if names["a"] != "lim_3" || names["b"] != "lim_7" || names["b:quota"] != "lim_7q" {
		t.Fatalf("names = %v", names)
	}
	rs := nft.Ruleset{SSHPorts: []uint16{22}, EgressInterface: "eth0", Limits: limits}
	if err := nft.Validate(rs); err != nil {
		t.Fatalf("the names must be valid: %v", err)
	}

	groups := []*models.NodeGroup{{ID: "g-b", SetNo: 12}, {ID: "g-a", SetNo: 5}}
	rules := []*models.VPNFirewallRule{{ID: "r", Enabled: true, SourceType: "group", SourceGroupID: ptr("g-b"),
		DestType: "any", Protocol: "all", Action: "accept"}}
	got, sets, errs := vpnRulesWithGroups(rules, nil, nil, groups)
	if len(errs) != 0 || len(got) != 1 || got[0].SrcSet != "grp_12" || len(sets) != 1 || sets[0].Name != "grp_12" {
		t.Fatalf("rules %+v sets %+v errs %v", got, sets, errs)
	}
}

// The name limit counts characters, not bytes ("ə" is two bytes).
func TestLimitProfileNameCountsCharacters(t *testing.T) {
	if err := ValidateLimitProfile(models.LimitProfile{Name: strings.Repeat("ə", 60), Timezone: "UTC", DownKbps: intp(1000)}); err != nil {
		t.Fatalf("60 characters: %v", err)
	}
	if err := ValidateLimitProfile(models.LimitProfile{Name: strings.Repeat("ə", 101), Timezone: "UTC", DownKbps: intp(1000)}); err == nil {
		t.Fatal("101 characters must be refused")
	}
}
