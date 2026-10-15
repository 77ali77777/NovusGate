package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

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
	if name := strings.TrimSpace(p.Name); name == "" || len(name) > 100 {
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
	if p.DownKbps == nil && p.UpKbps == nil && p.MaxConnections == nil && len(p.Schedule) == 0 {
		return fmt.Errorf("a profile needs a speed limit, a connection limit or a schedule")
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
		l := nft.Limit{Name: fmt.Sprintf("lim_%d", len(out)), ID: p.ID, Members: members[id]}
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
