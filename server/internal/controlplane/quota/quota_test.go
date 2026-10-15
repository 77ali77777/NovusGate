package quota

import (
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// The period starts on the reset day at local midnight: this month's if it
// has passed, else last month's.
func TestPeriodStart(t *testing.T) {
	baku := mustLoc(t, "Asia/Baku")
	for _, c := range []struct {
		now  time.Time
		day  int
		want time.Time
	}{
		{time.Date(2026, 10, 15, 12, 0, 0, 0, baku), 1, time.Date(2026, 10, 1, 0, 0, 0, 0, baku)},
		{time.Date(2026, 10, 15, 12, 0, 0, 0, baku), 20, time.Date(2026, 9, 20, 0, 0, 0, 0, baku)},
		{time.Date(2026, 10, 20, 0, 0, 0, 0, baku), 20, time.Date(2026, 10, 20, 0, 0, 0, 0, baku)},
		{time.Date(2026, 1, 5, 0, 0, 0, 0, baku), 10, time.Date(2025, 12, 10, 0, 0, 0, 0, baku)},
		// 23:30 UTC on Oct 19 is already Oct 20 in Baku.
		{time.Date(2026, 10, 19, 23, 30, 0, 0, time.UTC), 20, time.Date(2026, 10, 20, 0, 0, 0, 0, baku)},
	} {
		if got := PeriodStart(c.now, c.day, baku); !got.Equal(c.want) {
			t.Errorf("PeriodStart(%v, %d) = %v, want %v", c.now, c.day, got, c.want)
		}
	}
}

func gb(n float64) int64 { return int64(n * 1e9) }

var tz = time.UTC

func profile() Profile {
	return Profile{QuotaBytes: gb(10), ResetDay: 1, Loc: tz}
}

// The first sample only sets the baseline; later ones add rx+tx deltas.
func TestAdvanceCountsDeltas(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, tz)
	st, ev := Advance(State{}, profile(), 1000, 500, now)
	if st.UsedBytes != 0 || !st.HasLast || len(ev) != 0 {
		t.Fatalf("baseline = %+v %v", st, ev)
	}
	st, _ = Advance(st, profile(), 3000, 1500, now.Add(5*time.Minute))
	if st.UsedBytes != 3000 {
		t.Fatalf("used = %d, want 3000", st.UsedBytes)
	}
}

// A counter that went down (the interface came up again) counts from zero.
func TestAdvanceCounterReset(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, tz)
	st, _ := Advance(State{}, profile(), 9000, 9000, now)
	st, _ = Advance(st, profile(), 400, 100, now.Add(5*time.Minute))
	if st.UsedBytes != 500 {
		t.Fatalf("used = %d, want 500", st.UsedBytes)
	}
}

// 80% warns once, 100% exceeds once.
func TestAdvanceThresholds(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, tz)
	st, _ := Advance(State{}, profile(), 0, 0, now)
	st, ev := Advance(st, profile(), gb(7.9), 0, now.Add(time.Minute))
	if len(ev) != 0 {
		t.Fatalf("79%%: events %v", ev)
	}
	st, ev = Advance(st, profile(), gb(8), 0, now.Add(2*time.Minute))
	if len(ev) != 1 || ev[0] != Warned || st.WarnedAt == nil {
		t.Fatalf("80%%: %v %+v", ev, st)
	}
	st, ev = Advance(st, profile(), gb(9), 0, now.Add(3*time.Minute))
	if len(ev) != 0 {
		t.Fatalf("90%%: the warning repeats: %v", ev)
	}
	st, ev = Advance(st, profile(), gb(10), 0, now.Add(4*time.Minute))
	if len(ev) != 1 || ev[0] != Exceeded || st.ExceededAt == nil {
		t.Fatalf("100%%: %v %+v", ev, st)
	}
	_, ev = Advance(st, profile(), gb(12), 0, now.Add(5*time.Minute))
	if len(ev) != 0 {
		t.Fatalf("past 100%%: repeats %v", ev)
	}
}

// One large sample can cross both thresholds.
func TestAdvanceBothThresholdsAtOnce(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, tz)
	st, _ := Advance(State{}, profile(), 0, 0, now)
	_, ev := Advance(st, profile(), gb(11), 0, now.Add(time.Minute))
	if len(ev) != 2 || ev[0] != Warned || ev[1] != Exceeded {
		t.Fatalf("events = %v", ev)
	}
}

// A new period starts from zero and lifts an exceeded quota; the traffic of
// the sample that crosses the boundary counts in the new period.
func TestAdvanceNewPeriod(t *testing.T) {
	end := time.Date(2026, 10, 31, 23, 55, 0, 0, tz)
	st, _ := Advance(State{}, profile(), 0, 0, end.Add(-time.Hour))
	st, _ = Advance(st, profile(), gb(10), 0, end)
	if st.ExceededAt == nil {
		t.Fatal("must be exceeded")
	}
	st, ev := Advance(st, profile(), gb(10)+700, 0, end.Add(10*time.Minute))
	if len(ev) != 1 || ev[0] != Lifted {
		t.Fatalf("events = %v", ev)
	}
	if st.UsedBytes != 700 || st.ExceededAt != nil || st.WarnedAt != nil ||
		!st.PeriodStart.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, tz)) {
		t.Fatalf("new period = %+v", st)
	}
}

// Rollover lifts a quota at the period change even without a sample (a
// blocked node may send nothing).
func TestRollover(t *testing.T) {
	end := time.Date(2026, 10, 31, 23, 0, 0, 0, tz)
	st, _ := Advance(State{}, profile(), 0, 0, end.Add(-time.Hour))
	st, _ = Advance(st, profile(), gb(10), 0, end)
	st, ev := Rollover(st, profile(), end.Add(30*time.Minute))
	if len(ev) != 0 || st.ExceededAt == nil {
		t.Fatalf("same period: %v %+v", ev, st)
	}
	st, ev = Rollover(st, profile(), end.Add(2*time.Hour))
	if len(ev) != 1 || ev[0] != Lifted || st.UsedBytes != 0 || st.ExceededAt != nil || !st.HasLast {
		t.Fatalf("new period: %v %+v", ev, st)
	}
}

// Reset (the panel's "reset now") starts the count again and lifts the block.
func TestReset(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, tz)
	st, _ := Advance(State{}, profile(), 0, 0, now)
	st, _ = Advance(st, profile(), gb(10), 0, now.Add(time.Minute))
	st = Reset(st)
	if st.UsedBytes != 0 || st.ExceededAt != nil || st.WarnedAt != nil || !st.HasLast || st.LastRx != gb(10) {
		t.Fatalf("reset = %+v", st)
	}
}
