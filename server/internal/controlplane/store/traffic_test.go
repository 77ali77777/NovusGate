package store

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/traffic"
	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestTrafficSamplesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM node_traffic_samples"); err != nil {
		t.Fatal(err)
	}
	netw := &models.Network{Name: "traffic-net", CIDR: "10.77.0.0/24", InterfaceName: "wg77", ListenPort: 51877}
	if err := s.CreateNetwork(ctx, netw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteNetwork(context.Background(), netw.ID) })
	node := &models.Node{NetworkID: netw.ID, Name: "traffic-node", VirtualIP: net.ParseIP("10.77.0.2"),
		PublicKey: "TRAFFICKEY000000000000000000000000000000000=", Labels: map[string]string{}, Status: models.NodeStatusOnline}
	if err := s.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var in []traffic.Sample
	for i := 0; i < 4; i++ {
		in = append(in, traffic.Sample{NodeID: node.ID, At: base.Add(time.Duration(i*5) * time.Minute), Rx: int64(100 * i), Tx: int64(10 * i)})
	}
	if err := s.InsertTrafficSamples(ctx, in); err != nil {
		t.Fatal(err)
	}

	// From minute 10: the sample at minute 5 comes too, to seed the first delta.
	got, err := s.ListTrafficSamples(ctx, node.ID, base.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[0].At.Equal(base.Add(5*time.Minute)) || got[2].Rx != 300 {
		t.Fatalf("samples = %+v", got)
	}

	n, err := s.DeleteTrafficSamplesBefore(ctx, base.Add(10*time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v; want 2", n, err)
	}

	// Samples go with their node.
	if err := s.DeleteNode(ctx, node.ID); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM node_traffic_samples WHERE node_id = $1", node.ID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("samples left after the node was deleted: %d, %v", left, err)
	}
}
