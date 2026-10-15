package firewall

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// limitStore is a memStore that also keeps limit profiles (P9b).
type limitStore struct {
	*memStore
	profiles []models.LimitProfile
	limits   []models.NodeLimit
}

func (l *limitStore) ListLimitProfiles(context.Context) ([]models.LimitProfile, error) {
	return l.profiles, nil
}
func (l *limitStore) ListNodeLimits(context.Context) ([]models.NodeLimit, error) {
	return l.limits, nil
}

// Limit profiles reach the applied ruleset, and the engine reloads it when a
// profile's time zone changes its offset (New York leaves summer time on
// 2026-11-01 at 06:00 UTC), so schedules keep matching local time.
func TestEngineAppliesLimitsAndReloadsAtOffsetChange(t *testing.T) {
	h := newHarness(ModeNft)
	down := 2000
	h.e.Store = &limitStore{memStore: h.st,
		profiles: []models.LimitProfile{{ID: "p1", Name: "office", DownKbps: &down, Timezone: "America/New_York",
			Schedule: []models.ScheduleWindow{{Days: []int{1, 2, 3, 4, 5}, From: "09:00", To: "17:00"}}}},
		limits: []models.NodeLimit{{NodeID: "node-7", VirtualIP: "10.20.0.7", ProfileID: "p1"}},
	}
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	applied := h.r.applied[len(h.r.applied)-1]
	for _, s := range []string{
		"jump limits",
		`update @lim_0_down { ip daddr limit rate over 250000 bytes/second burst 250000 bytes }`,
		// 09:00 EDT is 13:00 UTC until November 1st.
		`meta day "Tuesday" meta hour "13:00:00"-"20:59:59" return`,
	} {
		if !strings.Contains(applied, s) {
			t.Errorf("applied ruleset lacks %q:\n%s", s, applied)
		}
	}
	change := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	if want := change.Sub(engineNow) + time.Second; h.expiryIn != want {
		t.Fatalf("next reload in %v, want %v (the offset change)", h.expiryIn, want)
	}
}

// Without limit profiles nothing is scheduled for time zones.
func TestEngineWithoutLimitsSchedulesNothing(t *testing.T) {
	h := newHarness(ModeNft)
	h.e.Store = &limitStore{memStore: h.st}
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(h.timers) != 0 {
		t.Fatalf("timers = %v, want none", h.timers)
	}
	if strings.Contains(h.r.applied[len(h.r.applied)-1], "limits") {
		t.Fatal("no limits expected")
	}
}
