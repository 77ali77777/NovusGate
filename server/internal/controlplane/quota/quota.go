// Package quota counts each node's monthly VPN traffic against its limit
// profile's quota (P9c). The count is kept incrementally (node_quota_state):
// samples are kept for 30 days, and a period can be 31.
package quota

import "time"

// Profile is the quota part of a limit profile.
type Profile struct {
	QuotaBytes int64 // per period; 0 = no quota
	ResetDay   int   // 1-28: the period starts on this day at local midnight
	Loc        *time.Location
}

// State is one node's count in the current period.
type State struct {
	NodeID      string
	PeriodStart time.Time
	// PeriodEnd is fixed when the period starts: a reset day or time zone
	// changed later applies from the next period.
	PeriodEnd  time.Time
	UsedBytes  int64
	LastRx     int64 // the WireGuard counters of the last sample
	LastTx     int64
	HasLast    bool
	LastAt     time.Time  // when the last sample was taken (zero: unknown)
	WarnedAt   *time.Time // 80% reached in this period
	ExceededAt *time.Time // 100% reached in this period
}

// Event is what changed with a sample.
type Event string

const (
	Warned   Event = "warned"   // 80% of the quota used
	Exceeded Event = "exceeded" // the quota is used up
	Lifted   Event = "lifted"   // an exceeded quota no longer applies (new period, raised quota, reset)
)

// WarnPercent is the share of the quota that sends a warning.
const WarnPercent = 80

// PeriodStart is the start of the period containing now: the reset day at
// local midnight, this month's if it has passed, else last month's.
func PeriodStart(now time.Time, resetDay int, loc *time.Location) time.Time {
	local := now.In(loc)
	start := time.Date(local.Year(), local.Month(), resetDay, 0, 0, 0, 0, loc)
	if local.Before(start) {
		start = time.Date(local.Year(), local.Month()-1, resetDay, 0, 0, 0, 0, loc)
	}
	return start
}

// delta is the traffic between two cumulative counter readings; a counter
// that went down (the interface came up again) counts from zero.
func delta(prev, cur int64) int64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// NextPeriodStart is the start of the period after the one starting at start.
func NextPeriodStart(start time.Time, resetDay int, loc *time.Location) time.Time {
	s := start.In(loc)
	return time.Date(s.Year(), s.Month()+1, resetDay, 0, 0, 0, 0, loc)
}

// newPeriod starts a period when there is none or now reached the end of
// the stored one; the new one follows the profile's current settings.
func newPeriod(st State, p Profile, now time.Time) (State, []Event) {
	if !st.PeriodEnd.IsZero() && now.Before(st.PeriodEnd) {
		return st, nil
	}
	var events []Event
	if st.ExceededAt != nil {
		events = append(events, Lifted)
	}
	start := PeriodStart(now, p.ResetDay, p.Loc)
	st.PeriodStart, st.PeriodEnd = start, NextPeriodStart(start, p.ResetDay, p.Loc)
	st.UsedBytes, st.WarnedAt, st.ExceededAt = 0, nil, nil
	return st, events
}

// evaluate sets or clears the 80% and 100% marks against the current quota,
// so raising the quota lifts a block and lowering it blocks.
func evaluate(st State, p Profile, now time.Time, events []Event) (State, []Event) {
	if p.QuotaBytes <= 0 {
		return st, events
	}
	at := now
	warn := st.UsedBytes*100 >= p.QuotaBytes*WarnPercent
	switch {
	case warn && st.WarnedAt == nil:
		st.WarnedAt = &at
		events = append(events, Warned)
	case !warn:
		st.WarnedAt = nil
	}
	over := st.UsedBytes >= p.QuotaBytes
	switch {
	case over && st.ExceededAt == nil:
		st.ExceededAt = &at
		events = append(events, Exceeded)
	case !over && st.ExceededAt != nil:
		st.ExceededAt = nil
		events = append(events, Lifted)
	}
	return st, events
}

// Rollover starts a new period when now reached the end of the stored one
// and re-checks the count against the current quota. It runs on its own for
// nodes that send nothing (a blocked node may not), so a block is lifted on
// time.
func Rollover(st State, p Profile, now time.Time) (State, []Event) {
	st, events := newPeriod(st, p, now)
	return evaluate(st, p, now, events)
}

// Advance adds one sample (cumulative rx and tx) to the count. The first
// sample only sets the baseline.
func Advance(st State, p Profile, rx, tx int64, now time.Time) (State, []Event) {
	oldEnd := st.PeriodEnd
	st, events := newPeriod(st, p, now)
	if st.HasLast {
		d := delta(st.LastRx, rx) + delta(st.LastTx, tx)
		// The gap since the last sample crosses the period end: only the
		// part after it, by time, belongs to the new period.
		if !oldEnd.IsZero() && !st.LastAt.IsZero() && st.LastAt.Before(oldEnd) && now.After(oldEnd) {
			d = int64(float64(d) * float64(now.Sub(oldEnd)) / float64(now.Sub(st.LastAt)))
		}
		st.UsedBytes += d
	}
	st.LastRx, st.LastTx, st.HasLast, st.LastAt = rx, tx, true, now
	return evaluate(st, p, now, events)
}

// Reset starts the count of the current period again and lifts the quota;
// the counter baseline is kept.
func Reset(st State) State {
	st.UsedBytes, st.WarnedAt, st.ExceededAt = 0, nil, nil
	return st
}
