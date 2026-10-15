// Package traffic records node transfer counters over time (P8) and turns
// them into per-interval traffic for the panel.
package traffic

import (
	"context"
	"log/slog"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// Sample is a node's cumulative WireGuard transfer counters (as the hub
// reports them for the peer) at one moment.
type Sample struct {
	NodeID string
	At     time.Time
	Rx     int64
	Tx     int64
}

// Point is the traffic of one interval starting at At.
type Point struct {
	At time.Time `json:"t"`
	Rx int64     `json:"rx"`
	Tx int64     `json:"tx"`
}

// Series turns one node's cumulative samples, sorted by time, into the
// bytes transferred per bucket: buckets equal intervals from from to to.
// A delta belongs to the bucket of its later sample. A counter that went
// down (the interface came up again) counts from zero.
func Series(samples []Sample, from, to time.Time, buckets int) []Point {
	if buckets < 1 || !to.After(from) {
		return []Point{}
	}
	width := to.Sub(from) / time.Duration(buckets)
	if width <= 0 {
		width = 1
	}
	points := make([]Point, buckets)
	for i := range points {
		points[i].At = from.Add(time.Duration(i) * width)
	}
	for i := 1; i < len(samples); i++ {
		cur := samples[i]
		if cur.At.Before(from) || !cur.At.Before(to) {
			continue
		}
		b := int(cur.At.Sub(from) / width)
		if b >= buckets {
			b = buckets - 1
		}
		points[b].Rx += delta(samples[i-1].Rx, cur.Rx)
		points[b].Tx += delta(samples[i-1].Tx, cur.Tx)
	}
	return points
}

func delta(prev, cur int64) int64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// Store is what the sampler needs from the database.
type Store interface {
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	ListNodes(ctx context.Context, networkID string) ([]*models.Node, error)
	InsertTrafficSamples(ctx context.Context, samples []Sample) error
	DeleteTrafficSamplesBefore(ctx context.Context, t time.Time) (int64, error)
}

// Sampler stores every node's counters and drops samples past Retention.
type Sampler struct {
	Store     Store
	Peers     func(iface string) (map[string]wireguard.PeerStatus, error)
	Now       func() time.Time
	Retention time.Duration
	// After, when set, gets each run's samples (the quota tracker, P9c);
	// it also runs when there are none, so periods roll over on time.
	After func(ctx context.Context, samples []Sample)
}

// RunOnce takes one sample of every node a WireGuard interface reports. An
// interface that cannot be read (down) is skipped: its nodes get no sample.
func (s *Sampler) RunOnce(ctx context.Context) error {
	now := s.Now()
	// After runs on every run, also a failed one (with what was read, or
	// nothing), so quota periods roll over while sampling fails.
	var samples []Sample
	if s.After != nil {
		defer func() { s.After(ctx, samples) }()
	}
	networks, err := s.Store.ListNetworks(ctx)
	if err != nil {
		return err
	}
	for _, n := range networks {
		peers, err := s.Peers(n.InterfaceName)
		if err != nil {
			slog.Debug("traffic: interface not read", "interface", n.InterfaceName, "error", err)
			continue
		}
		nodes, err := s.Store.ListNodes(ctx, n.ID)
		if err != nil {
			samples = nil // a partial run counts nothing
			return err
		}
		for _, node := range nodes {
			if p, ok := peers[node.PublicKey]; ok {
				samples = append(samples, Sample{NodeID: node.ID, At: now, Rx: p.TransferRx, Tx: p.TransferTx})
			}
		}
	}
	if len(samples) > 0 {
		if err := s.Store.InsertTrafficSamples(ctx, samples); err != nil {
			return err
		}
	}
	_, err = s.Store.DeleteTrafficSamplesBefore(ctx, now.Add(-s.Retention))
	return err
}

// Run samples every interval until ctx ends; errors are logged, not fatal.
func (s *Sampler) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.RunOnce(ctx); err != nil {
			slog.Warn("traffic sample failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
