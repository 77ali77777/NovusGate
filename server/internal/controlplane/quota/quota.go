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
	UsedBytes   int64
	LastRx      int64 // the WireGuard counters of the last sample
	LastTx      int64
	HasLast     bool
	WarnedAt    *time.Time // 80% reached in this period
	ExceededAt  *time.Time // 100% reached in this period
}

// Event is what changed with a sample.
type Event string

const (
	Warned   Event = "warned"   // 80% of the quota used
	Exceeded Event = "exceeded" // the quota is used up
	Lifted   Event = "lifted"   // an exceeded quota no longer applies (new period)
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

// Rollover starts a new period when now is past the stored one. It is
// applied before every sample and on its own for nodes that send nothing
// (a blocked node may not), so a block is lifted on time.
func Rollover(st State, p Profile, now time.Time) (State, []Event) {
	start := PeriodStart(now, p.ResetDay, p.Loc)
	if st.PeriodStart.Equal(start) {
		return st, nil
	}
	var events []Event
	if st.ExceededAt != nil {
		events = append(events, Lifted)
	}
	st.PeriodStart, st.UsedBytes, st.WarnedAt, st.ExceededAt = start, 0, nil, nil
	return st, events
}

// Advance adds one sample (cumulative rx and tx) to the count. The first
// sample only sets the baseline.
func Advance(st State, p Profile, rx, tx int64, now time.Time) (State, []Event) {
	st, events := Rollover(st, p, now)
	if st.HasLast {
		st.UsedBytes += delta(st.LastRx, rx) + delta(st.LastTx, tx)
	}
	st.LastRx, st.LastTx, st.HasLast = rx, tx, true
	if p.QuotaBytes <= 0 {
		return st, events
	}
	at := now
	if st.WarnedAt == nil && st.UsedBytes*100 >= p.QuotaBytes*WarnPercent {
		st.WarnedAt = &at
		events = append(events, Warned)
	}
	if st.ExceededAt == nil && st.UsedBytes >= p.QuotaBytes {
		st.ExceededAt = &at
		events = append(events, Exceeded)
	}
	return st, events
}

// Reset starts the count of the current period again and lifts the quota;
// the counter baseline is kept.
func Reset(st State) State {
	st.UsedBytes, st.WarnedAt, st.ExceededAt = 0, nil, nil
	return st
}
