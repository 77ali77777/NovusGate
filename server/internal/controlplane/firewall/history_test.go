package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

type memHistory struct {
	entries []*models.FirewallHistoryEntry
	calls   int // InsertFirewallHistory calls (one transaction each)
	err     error
	block   bool // wait for the context like a hung database
}

func (m *memHistory) InsertFirewallHistory(ctx context.Context, es ...*models.FirewallHistoryEntry) error {
	if m.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if m.err != nil {
		return m.err
	}
	m.calls++
	m.entries = append(m.entries, es...)
	return nil
}

func (m *memHistory) HasFirewallHistory(context.Context) (bool, error) {
	return len(m.entries) > 0, nil
}

func historyServices(t *testing.T, e *models.FirewallHistoryEntry) int {
	t.Helper()
	var st State
	if err := json.Unmarshal(e.State, &st); err != nil {
		t.Fatal(err)
	}
	return len(st.Services)
}

// The first recorded change also stores the state before it, so its diff
// has a base; later changes add one entry each, with who made them.
func TestHistoryRecordsAppliedChanges(t *testing.T) {
	h := newHarness(ModeNft)
	hist := &memHistory{}
	h.e.History = hist
	commits := 0
	ctx := WithActor(context.Background(), Actor{Label: "POST /api/v1/firewall/v2/services", UserID: "u1"})
	if _, err := h.e.Propose(ctx, openPort(h, 443, &commits), false, nil); err != nil {
		t.Fatal(err)
	}
	if len(hist.entries) != 2 || hist.entries[0].Action != "baseline" || historyServices(t, hist.entries[0]) != 0 ||
		hist.entries[1].Action != "POST /api/v1/firewall/v2/services" || hist.entries[1].UserID != "u1" || historyServices(t, hist.entries[1]) != 1 {
		t.Fatalf("entries = %+v", hist.entries)
	}
	if _, err := h.e.Propose(ctx, openPort(h, 9000, &commits), false, nil); err != nil {
		t.Fatal(err)
	}
	if len(hist.entries) != 3 || historyServices(t, hist.entries[2]) != 2 {
		t.Fatalf("entries = %d", len(hist.entries))
	}
	// A reconcile changes nothing stored: no entry.
	if _, err := h.e.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(hist.entries) != 3 {
		t.Fatalf("reconcile recorded %d entries", len(hist.entries))
	}
}

// A change waiting for confirmation is recorded when it is confirmed, with
// the actor of the request that proposed it; a rolled-back one never.
func TestHistoryWaitsForConfirmation(t *testing.T) {
	h := newHarness(ModeNft)
	hist := &memHistory{}
	h.e.History = hist
	commits := 0
	ctx := WithActor(context.Background(), Actor{Label: "add 443", UserID: "u2"})
	res, err := h.e.Propose(ctx, openPort(h, 443, &commits), true, nil)
	if err != nil || res.Pending == nil {
		t.Fatalf("propose = %+v %v", res, err)
	}
	if len(hist.entries) != 0 {
		t.Fatal("pending change recorded too early")
	}
	if err := h.e.Confirm(context.Background(), res.Pending.ID); err != nil {
		t.Fatal(err)
	}
	if len(hist.entries) != 2 || hist.entries[1].Action != "add 443" || hist.entries[1].UserID != "u2" {
		t.Fatalf("entries = %+v", hist.entries)
	}

	h2 := newHarness(ModeNft)
	hist2 := &memHistory{}
	h2.e.History = hist2
	if _, err := h2.e.Propose(ctx, openPort(h2, 443, &commits), true, nil); err != nil {
		t.Fatal(err)
	}
	h2.rollback() // the confirmation window ran out
	if len(hist2.entries) != 0 {
		t.Fatalf("rolled-back change recorded: %+v", hist2.entries)
	}
}

func TestHistoryFailureDoesNotFailTheChange(t *testing.T) {
	h := newHarness(ModeNft)
	h.e.History = &memHistory{err: errors.New("db down")}
	commits := 0
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); err != nil || commits != 1 {
		t.Fatalf("propose = %v commits %d", err, commits)
	}
}

// The baseline and the first change are stored together or not at all.
func TestHistoryBaselineAndChangeInOneTransaction(t *testing.T) {
	h := newHarness(ModeNft)
	hist := &memHistory{}
	h.e.History = hist
	commits := 0
	if _, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil); err != nil {
		t.Fatal(err)
	}
	if hist.calls != 1 || len(hist.entries) != 2 {
		t.Fatalf("calls %d entries %d", hist.calls, len(hist.entries))
	}
}

// A hung database must not hold the engine lock for ever.
func TestHistoryWriteTimesOut(t *testing.T) {
	orig := historyTimeout
	historyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { historyTimeout = orig })
	h := newHarness(ModeNft)
	h.e.History = &memHistory{block: true}
	commits := 0
	done := make(chan error, 1)
	go func() {
		_, err := h.e.Propose(context.Background(), openPort(h, 443, &commits), false, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Propose is stuck on the history write")
	}
}
