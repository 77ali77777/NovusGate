package reconciler

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// panicStore panics on its first ListNetworks call.
type panicStore struct {
	*fakeStore
	calls atomic.Int32
	block chan struct{} // when set, ListNetworks waits on it
}

func (p *panicStore) ListNetworks(ctx context.Context) ([]*models.Network, error) {
	if p.calls.Add(1) == 1 && p.block == nil {
		panic("boom")
	}
	if p.block != nil {
		<-p.block
	}
	return p.fakeStore.ListNetworks(ctx)
}

func TestRunSurvivesAPanickingRun(t *testing.T) {
	_, st, wg := setup(ModeShadow)
	ps := &panicStore{fakeStore: st}
	r := New(ModeShadow, ps, func(string) PeerControl { return wg })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, time.Hour)
	r.Trigger()
	time.Sleep(50 * time.Millisecond)
	r.Trigger()
	deadline := time.Now().Add(2 * time.Second)
	for ps.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ps.calls.Load() < 2 {
		t.Fatal("the loop must keep running after a panicking run")
	}
}

func TestWaitReturnsAfterTheRunningTick(t *testing.T) {
	_, st, wg := setup(ModeShadow)
	ps := &panicStore{fakeStore: st, block: make(chan struct{})}
	r := New(ModeShadow, ps, func(string) PeerControl { return wg })
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx, time.Hour)
	r.Trigger()
	for ps.calls.Load() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("Wait returned while a run was still in progress")
	case <-time.After(50 * time.Millisecond):
	}
	close(ps.block)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait must return once the running tick ends")
	}
}

// A public key shared by an active and an inactive node: the peer stays
// (the active node needs it) and the conflict is reported, not flapped.
func TestDuplicateKeyDoesNotFlap(t *testing.T) {
	past := now.Add(-time.Hour)
	nw := &models.Network{ID: "n1", InterfaceName: "wg1"}
	nodes := []*models.Node{
		node("a", "n1", "x", "10.20.0.3", models.NodeStatusOnline, nil),
		node("b", "n1", "x", "10.20.0.4", models.NodeStatusExpired, &past),
	}
	live := map[string]wireguard.PeerStatus{key("x"): {AllowedIPs: "10.20.0.3/32"}}
	actions, _, dups := plan(nw, nodes, live, now)
	for _, a := range actions {
		if a.Kind == "remove" {
			t.Fatalf("the active node's peer must not be removed: %+v", a)
		}
	}
	if len(dups) != 1 || !strings.Contains(dups[0], "node-a") || !strings.Contains(dups[0], "node-b") {
		t.Fatalf("duplicates = %v", dups)
	}
}

// Shadow findings are logged when they appear, not on every tick.
func TestShadowFindingsAreLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	orig := slog.Default()
	origOut, origFlags := log.Writer(), log.Flags() // slog.SetDefault also redirects the log package
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer func() {
		slog.SetDefault(orig)
		log.SetOutput(origOut)
		log.SetFlags(origFlags)
	}()
	r, _, _ := setup(ModeShadow)
	r.RunOnce(context.Background())
	r.RunOnce(context.Background())
	out := buf.String()
	if n := strings.Count(out, "would change peer"); n != 2 { // b (add) and d (update), once each
		t.Fatalf("'would change peer' logged %d times, want 2:\n%s", n, out)
	}
	if n := strings.Count(out, "peer not in the database"); n != 1 {
		t.Fatalf("unknown peer logged %d times, want 1:\n%s", n, out)
	}
}

func TestRunTwiceDoesNotPanic(t *testing.T) {
	r, _, _ := setup(ModeShadow)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx, time.Hour)
	time.Sleep(20 * time.Millisecond)
	r.Run(ctx, time.Hour) // returns at once
	cancel()
	r.Wait()
}
