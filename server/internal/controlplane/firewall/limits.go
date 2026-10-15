package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Bounds of a limit profile (P9b).
const (
	MaxLimitKbps        = 100_000_000 // 100 Gbit/s
	MaxLimitConnections = 1_000_000
	MaxScheduleWindows  = 28
)

var clockRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ValidateLimitProfile checks a profile before it is stored.
func ValidateLimitProfile(p models.LimitProfile) error {
	if name := strings.TrimSpace(p.Name); name == "" || utf8.RuneCountInString(name) > 100 { // characters, not bytes
		return fmt.Errorf("name must be 1-100 characters")
	}
	for label, v := range map[string]*int{"down_kbps": p.DownKbps, "up_kbps": p.UpKbps} {
		if v != nil && (*v < 1 || *v > MaxLimitKbps) {
			return fmt.Errorf("%s must be 1-%d", label, MaxLimitKbps)
		}
	}
	if p.MaxConnections != nil && (*p.MaxConnections < 1 || *p.MaxConnections > MaxLimitConnections) {
		return fmt.Errorf("max_connections must be 1-%d", MaxLimitConnections)
	}
	if p.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}
	if _, err := time.LoadLocation(p.Timezone); err != nil {
		return fmt.Errorf("unknown timezone %q", p.Timezone)
	}
	if len(p.Schedule) > MaxScheduleWindows {
		return fmt.Errorf("at most %d schedule windows", MaxScheduleWindows)
	}
	for i, w := range p.Schedule {
		if len(w.Days) == 0 {
			return fmt.Errorf("schedule window %d: no days", i+1)
		}
		seen := map[int]bool{}
		for _, d := range w.Days {
			if d < 0 || d > 6 || seen[d] {
				return fmt.Errorf("schedule window %d: days must be distinct values 0-6", i+1)
			}
			seen[d] = true
		}
		if !clockRe.MatchString(w.From) {
			return fmt.Errorf("schedule window %d: from must be HH:MM (00:00-23:59)", i+1)
		}
		if w.To != "24:00" && !clockRe.MatchString(w.To) {
			return fmt.Errorf("schedule window %d: to must be HH:MM or 24:00", i+1)
		}
		if w.From == w.To {
			return fmt.Errorf("schedule window %d: from and to are equal", i+1)
		}
	}
	if err := validateQuota(p); err != nil {
		return err
	}
	if p.DownKbps == nil && p.UpKbps == nil && p.MaxConnections == nil && len(p.Schedule) == 0 && p.QuotaMB == nil {
		return fmt.Errorf("a profile needs a speed limit, a connection limit, a schedule or a quota")
	}
	return nil
}

// clockSeconds parses a validated HH:MM (or 24:00) as seconds since midnight.
func clockSeconds(s string) (int, int) {
	var h, m int
	fmt.Sscanf(s, "%d:%d", &h, &m)
	return h, m
}

// UTCWindows turns a profile's local schedule into UTC day windows for the
// week around now (yesterday to five days ahead): each weekday uses the
// offset of that date, so a reload at every offset change
// (NextOffsetChange) keeps them exact.
// Windows that cross a UTC midnight are split.
func UTCWindows(schedule []models.ScheduleWindow, loc *time.Location, now time.Time) []nft.TimeWindow {
	today := now.In(loc)
	seen := map[nft.TimeWindow]bool{}
	var out []nft.TimeWindow
	for _, sw := range schedule {
		fh, fm := clockSeconds(sw.From)
		th, tm := clockSeconds(sw.To)
		for _, d := range sw.Days {
			// Dates from yesterday to five days ahead: a window that began
			// yesterday and is still running keeps yesterday's offset.
			offset := (d-int(today.Weekday())+8)%7 - 1
			y, mo, dd := today.AddDate(0, 0, offset).Date()
			start := time.Date(y, mo, dd, fh, fm, 0, 0, loc)
			end := time.Date(y, mo, dd, th, tm, 0, 0, loc)
			if !end.After(start) { // runs past midnight (24:00 included)
				end = time.Date(y, mo, dd+1, th%24, tm, 0, 0, loc)
			}
			for cur, stop := start.UTC(), end.UTC(); cur.Before(stop); {
				midnight := time.Date(cur.Year(), cur.Month(), cur.Day(), 0, 0, 0, 0, time.UTC)
				segEnd := midnight.Add(24 * time.Hour)
				if stop.Before(segEnd) {
					segEnd = stop
				}
				win := nft.TimeWindow{Day: cur.Weekday(), From: int(cur.Sub(midnight).Seconds()), To: int(segEnd.Sub(midnight).Seconds())}
				if !seen[win] {
					seen[win] = true
					out = append(out, win)
				}
				cur = segEnd
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day < out[j].Day
		}
		return out[i].From < out[j].From
	})
	return out
}

// NextOffsetChange returns the next instant (within about a year) at which
// loc's UTC offset changes, such as a daylight-saving switch.
func NextOffsetChange(loc *time.Location, now time.Time) (time.Time, bool) {
	_, base := now.In(loc).Zone()
	lo := now
	for day := 1; day <= 400; day++ {
		hi := now.Add(time.Duration(day) * 24 * time.Hour)
		if _, off := hi.In(loc).Zone(); off == base {
			lo = hi
			continue
		}
		// The change is in (lo, hi]: narrow it to the second.
		for hi.Sub(lo) > time.Second {
			mid := lo.Add(hi.Sub(lo) / 2).Truncate(time.Second)
			if _, off := mid.In(loc).Zone(); off == base {
				lo = mid
			} else {
				hi = mid
			}
		}
		return hi.UTC(), true
	}
	return time.Time{}, false
}

// LimitsFromModels builds the nft limits: one per profile that limited nodes
// use, named lim_<n> by profile ID order. Speeds are converted from kbit/s
// to bytes/s. A node with an unusable address or a profile with an unknown
// time zone is reported and skipped.
func LimitsFromModels(profiles []models.LimitProfile, nodes []models.NodeLimit, now time.Time) ([]nft.Limit, []error) {
	var warnings []error
	members := map[string][]netip.Addr{}
	for _, n := range nodes {
		addr, err := netip.ParseAddr(n.VirtualIP)
		if err != nil || !addr.Is4() {
			warnings = append(warnings, fmt.Errorf("limit: node %s has no usable IPv4 address %q", n.NodeID, n.VirtualIP))
			continue
		}
		members[n.ProfileID] = append(members[n.ProfileID], addr)
	}
	byID := map[string]models.LimitProfile{}
	var ids []string
	for _, p := range profiles {
		if len(members[p.ID]) == 0 {
			continue
		}
		byID[p.ID] = p
		ids = append(ids, p.ID)
	}
	sort.Strings(ids)
	var out []nft.Limit
	for _, id := range ids {
		p := byID[id]
		loc, err := time.LoadLocation(p.Timezone)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("limit profile %s: unknown timezone %q, not applied", p.Name, p.Timezone))
			continue
		}
		l := nft.Limit{Name: setName2("lim", p.SetNo, len(out)), ID: p.ID, Members: members[id]}
		if p.UpKbps != nil {
			l.UpBytes = uint64(*p.UpKbps) * 125
		}
		if p.DownKbps != nil {
			l.DownBytes = uint64(*p.DownKbps) * 125
		}
		if p.MaxConnections != nil {
			l.MaxConns = uint32(*p.MaxConnections)
		}
		l.Windows = UTCWindows(p.Schedule, loc, now)
		out = append(out, l)
	}
	return out, warnings
}

// MaxQuotaMB bounds a monthly quota (1 PB).
const MaxQuotaMB = 1_000_000_000

// validateQuota checks the quota settings (P9c); an empty action is block
// and reset day 0 is the 1st, as the store fills them in.
func validateQuota(p models.LimitProfile) error {
	if p.QuotaMB != nil && (*p.QuotaMB < 1 || *p.QuotaMB > MaxQuotaMB) {
		return fmt.Errorf("quota_mb must be 1-%d", MaxQuotaMB)
	}
	switch p.QuotaAction {
	case "", "block":
	case "throttle":
		if p.ThrottleKbps == nil {
			return fmt.Errorf("throttle_kbps is required when quota_action is throttle")
		}
	default:
		return fmt.Errorf("quota_action must be block or throttle")
	}
	if p.ThrottleKbps != nil && (*p.ThrottleKbps < 1 || *p.ThrottleKbps > MaxLimitKbps) {
		return fmt.Errorf("throttle_kbps must be 1-%d", MaxLimitKbps)
	}
	if p.QuotaResetDay < 0 || p.QuotaResetDay > 28 {
		return fmt.Errorf("quota_reset_day must be 1-28")
	}
	return nil
}

// ApplyQuotas enforces exceeded quotas (P9c) on the limits LimitsFromModels
// built: a node over the quota of its profile in the current period is
// blocked, or moved to a throttled copy of its profile (ID "<profile>:quota",
// both directions at throttle_kbps, other limits kept). A count from an
// earlier period no longer applies.
func ApplyQuotas(limits []nft.Limit, profiles []models.LimitProfile, nodes []models.NodeLimit,
	states []models.NodeQuotaState, now time.Time) ([]nft.Limit, []netip.Addr) {
	byID := map[string]models.LimitProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	stateOf := map[string]models.NodeQuotaState{}
	for _, st := range states {
		stateOf[st.NodeID] = st
	}
	var blocked []netip.Addr
	throttled := map[string][]netip.Addr{} // profile ID -> moved members
	for _, n := range nodes {
		p, ok := byID[n.ProfileID]
		st, has := stateOf[n.NodeID]
		// Over the current quota in a period that has not ended: the use is
		// compared with the quota now, so raising it lets the node go.
		if !ok || p.QuotaMB == nil || !has || !now.Before(st.PeriodEnd) || st.UsedBytes < int64(*p.QuotaMB)*1_000_000 {
			continue
		}
		addr, err := netip.ParseAddr(n.VirtualIP)
		if err != nil || !addr.Is4() {
			continue
		}
		if p.QuotaAction == "throttle" && p.ThrottleKbps != nil {
			throttled[p.ID] = append(throttled[p.ID], addr)
		} else {
			blocked = append(blocked, addr)
		}
	}
	ids := make([]string, 0, len(throttled))
	for id := range throttled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		moved := map[netip.Addr]bool{}
		for _, a := range throttled[id] {
			moved[a] = true
		}
		var base *nft.Limit
		for i := range limits {
			if limits[i].ID == id {
				base = &limits[i]
				kept := limits[i].Members[:0:0]
				for _, a := range limits[i].Members {
					if !moved[a] {
						kept = append(kept, a)
					}
				}
				limits[i].Members = kept
			}
		}
		rate := uint64(*byID[id].ThrottleKbps) * 125
		l := nft.Limit{Name: setName2("lim", byID[id].SetNo, len(limits)) + "q", ID: id + ":quota", Members: throttled[id],
			UpBytes: rate, DownBytes: rate}
		if base != nil {
			// Slowing down never makes a node faster than its profile.
			l.UpBytes, l.DownBytes = slower(rate, base.UpBytes), slower(rate, base.DownBytes)
			l.MaxConns, l.Windows = base.MaxConns, base.Windows
		}
		limits = append(limits, l)
	}
	return limits, blocked
}

// slower is the lower of two rates; 0 (no limit) never wins.
func slower(rate, base uint64) uint64 {
	if base > 0 && base < rate {
		return base
	}
	return rate
}
