package traffic

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func TestSeriesSumsDeltasPerBucket(t *testing.T) {
	samples := []Sample{
		{At: at(0), Rx: 100, Tx: 10},
		{At: at(5), Rx: 150, Tx: 30},  // +50 / +20
		{At: at(10), Rx: 250, Tx: 30}, // +100 / +0
		{At: at(25), Rx: 300, Tx: 35}, // +50 / +5
	}
	got := Series(samples, at(0), at(30), 3) // 10-minute buckets
	want := []Point{
		{At: at(0), Rx: 50, Tx: 20},
		{At: at(10), Rx: 100, Tx: 0},
		{At: at(20), Rx: 50, Tx: 5},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Series = %+v\nwant %+v", got, want)
	}
}

// WireGuard counters restart at 0 when the interface comes up again; the
// bytes since the restart are the new counter itself, never a negative delta.
func TestSeriesHandlesCounterReset(t *testing.T) {
	samples := []Sample{
		{At: at(0), Rx: 1000, Tx: 1000},
		{At: at(5), Rx: 40, Tx: 7},
	}
	got := Series(samples, at(0), at(10), 1)
	if len(got) != 1 || got[0].Rx != 40 || got[0].Tx != 7 {
		t.Fatalf("Series = %+v, want rx 40 tx 7", got)
	}
}

func TestSeriesEmptyAndOutOfRange(t *testing.T) {
	got := Series(nil, at(0), at(60), 4)
	if len(got) != 4 || got[0].At != at(0) || got[3].At != at(45) || got[2].Rx != 0 {
		t.Fatalf("an empty range still has its buckets: %+v", got)
	}
	// samples before "from" only seed the first delta; later ones are ignored
	samples := []Sample{{At: at(-5), Rx: 10}, {At: at(5), Rx: 30}, {At: at(70), Rx: 90}}
	got = Series(samples, at(0), at(60), 1)
	if got[0].Rx != 20 {
		t.Fatalf("Series = %+v, want 20 in range", got)
	}
}

type fakeStore struct {
	networks []*models.Network
	nodes    map[string][]*models.Node
	inserted []Sample
	cutoff   time.Time
}

func (f *fakeStore) ListNetworks(context.Context) ([]*models.Network, error) { return f.networks, nil }
func (f *fakeStore) ListNodes(_ context.Context, id string) ([]*models.Node, error) {
	return f.nodes[id], nil
}
func (f *fakeStore) InsertTrafficSamples(_ context.Context, s []Sample) error {
	f.inserted = append(f.inserted, s...)
	return nil
}
func (f *fakeStore) DeleteTrafficSamplesBefore(_ context.Context, t time.Time) (int64, error) {
	f.cutoff = t
	return 0, nil
}

func TestSamplerRecordsKnownPeersAndPrunes(t *testing.T) {
	st := &fakeStore{
		networks: []*models.Network{{ID: "n1", InterfaceName: "wg1"}, {ID: "n2", InterfaceName: "wg2"}},
		nodes: map[string][]*models.Node{
			"n1": {{ID: "a", PublicKey: "KA"}, {ID: "b", PublicKey: "KB"}},
			"n2": {{ID: "c", PublicKey: "KC"}},
		},
	}
	peers := map[string]map[string]wireguard.PeerStatus{
		"wg1": {"KA": {PublicKey: "KA", TransferRx: 5, TransferTx: 6}, "KX": {PublicKey: "KX", TransferRx: 1}},
	}
	s := &Sampler{
		Store:     st,
		Now:       func() time.Time { return t0 },
		Retention: 30 * 24 * time.Hour,
		Peers: func(iface string) (map[string]wireguard.PeerStatus, error) {
			if p, ok := peers[iface]; ok {
				return p, nil
			}
			return nil, errors.New("Unable to access interface") // wg2 is down
		},
	}
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []Sample{{NodeID: "a", At: t0, Rx: 5, Tx: 6}} // unknown peer KX and absent b are skipped
	if !reflect.DeepEqual(st.inserted, want) {
		t.Fatalf("inserted %+v, want %+v", st.inserted, want)
	}
	if !st.cutoff.Equal(t0.Add(-30 * 24 * time.Hour)) {
		t.Fatalf("pruned before %v", st.cutoff)
	}
}
