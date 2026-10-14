package rest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/traffic"
)

func TestNodeTrafficHistory(t *testing.T) {
	s, st, _ := newContractServer(t)
	seed := seedContract(t, st)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	orig := trafficNow
	trafficNow = func() time.Time { return now }
	t.Cleanup(func() { trafficNow = orig })

	// 24h: 288 five-minute buckets ending now; 300 bytes in the last hour.
	samples := []traffic.Sample{
		{NodeID: seed.node.ID, At: now.Add(-60 * time.Minute), Rx: 1000, Tx: 100},
		{NodeID: seed.node.ID, At: now.Add(-30 * time.Minute), Rx: 1200, Tx: 150},
		{NodeID: seed.node.ID, At: now.Add(-1 * time.Minute), Rx: 1300, Tx: 170},
	}
	if err := st.InsertTrafficSamples(context.Background(), samples); err != nil {
		t.Fatal(err)
	}
	rec := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID+"/traffic?range=24h", "", true)
	if rec.Code != 200 {
		t.Fatalf("traffic = %d %s", rec.Code, rec.Body)
	}
	var body NodeTrafficResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var rx, tx int64
	for _, p := range body.Points {
		rx += p.Rx
		tx += p.Tx
	}
	if body.Range != "24h" || body.BucketSeconds != 300 || len(body.Points) != 288 || rx != 300 || tx != 70 {
		t.Fatalf("range %s bucket %d points %d rx %d tx %d", body.Range, body.BucketSeconds, len(body.Points), rx, tx)
	}
	assertMatchesSpec(t, s, "GET", "/api/v1/nodes/{id}/traffic", rec)

	if rec := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID+"/traffic?range=1y", "", true); rec.Code != 400 {
		t.Fatalf("an unknown range = %d, want 400", rec.Code)
	}
	if rec := callAs(t, s, "GET", "/api/v1/nodes/00000000-0000-4000-8000-000000000000/traffic", "", true); rec.Code != 404 {
		t.Fatalf("a missing node = %d, want 404", rec.Code)
	}
	if rec := callAs(t, s, "GET", "/api/v1/nodes/"+seed.node.ID+"/traffic", "", true); rec.Code != 200 {
		t.Fatalf("the default range = %d, want 200", rec.Code)
	}
}
