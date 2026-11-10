package ingestion

import (
	"context"
	"testing"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type fakePostureRepo struct{ inserted []store.PosturePoint }

func (f *fakePostureRepo) BulkInsert(ctx context.Context, points []store.PosturePoint) error {
	f.inserted = append(f.inserted, points...)
	return nil
}
func (f *fakePostureRepo) QueryHistory(ctx context.Context, filter store.PostureFilter) ([]store.PosturePoint, error) {
	return nil, nil
}

func TestPostureWriterLastSampleWins(t *testing.T) {
	repo := &fakePostureRepo{}
	w := NewPostureWriter(repo, 15*time.Second)
	w.Enqueue("edge-1", &pb.StatsReport{Posture: &pb.NodePosture{EmergencyDrops: 10}})
	w.Enqueue("edge-1", &pb.StatsReport{Posture: &pb.NodePosture{EmergencyDrops: 25}})
	w.Enqueue("edge-2", &pb.StatsReport{Posture: &pb.NodePosture{EmergencyDrops: 7}})
	w.Enqueue("edge-1", &pb.StatsReport{Posture: nil}) // posture-less report is a no-op

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if len(repo.inserted) != 2 {
		t.Fatalf("want 2 rows (one per node), got %d", len(repo.inserted))
	}
	byNode := map[string]store.PosturePoint{}
	for _, p := range repo.inserted {
		byNode[p.NodeID] = p
	}
	if got := byNode["edge-1"].EmergencyDrops; got != 25 {
		t.Errorf("edge-1: want last sample 25, got %d", got)
	}
	if got := byNode["edge-2"].EmergencyDrops; got != 7 {
		t.Errorf("edge-2: want 7, got %d", got)
	}
	if byNode["edge-1"].Time.Location() != time.UTC {
		t.Errorf("flush time must be UTC-truncated, got %v", byNode["edge-1"].Time)
	}
}
