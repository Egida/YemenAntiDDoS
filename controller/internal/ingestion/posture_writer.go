package ingestion

import (
	"context"
	"log"
	"sync"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// PostureWriter persists per-node inline posture counters into ts_node_posture.
// Counters are cumulative, so the writer keeps only the LAST sample per node
// per flush window ("last sample wins") — no averaging, unlike DBWriter.
type PostureWriter struct {
	repo     store.NodePostureRepo
	interval time.Duration

	mu      sync.Mutex
	pending map[string]store.PosturePoint
}

func NewPostureWriter(repo store.NodePostureRepo, interval time.Duration) *PostureWriter {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &PostureWriter{
		repo:     repo,
		interval: interval,
		pending:  make(map[string]store.PosturePoint),
	}
}

// Enqueue records the latest posture of a Node. Reports without a posture
// (flow-only Nodes) are ignored.
func (w *PostureWriter) Enqueue(nodeID string, report *pb.StatsReport) {
	post := report.GetPosture()
	if nodeID == "" || post == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending[nodeID] = store.PosturePoint{
		NodeID:              nodeID,
		FilterRules:         post.GetFilterRules(),
		ValidatedClients:    post.GetValidatedClients(),
		SynCookiesReplied:   post.GetSynCookiesReply(),
		SynCookiesValidated: post.GetSynCookiesValidated(),
		SynCookiesDropped:   post.GetSynCookiesDropped(),
		EmergencyDrops:      post.GetEmergencyDrops(),
		BurstAlerts:         post.GetBurstAlerts(),
		RedirectOk:          post.GetRedirectOk(),
		RedirectErr:         post.GetRedirectErr(),
		DnsTxidDrops:        post.GetDnsTxidDrops(),
		PayloadSigDrops:     post.GetPayloadSigDrops(),
		PayloadSigPass:      post.GetPayloadSigPass(),
		AFXDPActive:         post.GetAfXdpActive(),
		AFXDPUmemDrops:      post.GetAfXdpUmemDrops(),
		AFXDPRX:             post.GetAfXdpRx(),
	}
}

// Run flushes every interval. Blocks until ctx is cancelled.
func (w *PostureWriter) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.flush(context.Background())
			return
		case <-ticker.C:
			w.flush(ctx)
		}
	}
}

func (w *PostureWriter) flush(ctx context.Context) {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return
	}
	batch := make([]store.PosturePoint, 0, len(w.pending))
	// All points in one flush share the same timestamp (truncated to flush interval),
	// matching DBWriter's flushTime pattern.
	flushTime := time.Now().UTC().Truncate(w.interval)
	for _, p := range w.pending {
		p.Time = flushTime
		batch = append(batch, p)
	}
	w.pending = make(map[string]store.PosturePoint)
	w.mu.Unlock()

	if err := w.repo.BulkInsert(ctx, batch); err != nil {
		// No requeue (unlike DBWriter): counters are cumulative and each report re-enqueues fresher data, so a dropped window only leaves a gap in history.
		log.Printf("posture_writer: insert %d rows failed: %v", len(batch), err)
	}
}
