package action

import (
	"context"
	"log"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type announcingObservation struct {
	gen       int
	firstSeen time.Time
}

// RunAnnouncingReconcile repairs labels only after a full observation interval.
func (e *Engine) RunAnnouncingReconcile(ctx context.Context, interval time.Duration) {
	observed := make(map[int]announcingObservation)
	for {
		if ctx.Err() != nil {
			return
		}
		rows, err := e.store.BGPAnnouncements().ListByStatus(ctx, "announcing")
		if err != nil {
			metrics.BGPAnnouncingReconcile.WithLabelValues("list_error").Inc()
			log.Printf("action: announcing reconcile list: %v", err)
		} else {
			now := time.Now()
			next := make(map[int]announcingObservation, len(rows))
			for _, ann := range rows {
				seen, exists := observed[ann.ID]
				same := exists && seen.gen == ann.Gen
				if !same {
					seen = announcingObservation{gen: ann.Gen, firstSeen: now}
				}
				next[ann.ID] = seen
				if same && now.Sub(seen.firstSeen) >= interval {
					if e.reconcileAnnouncing(ctx, ann) {
						delete(next, ann.ID)
					}
				}
			}
			observed = next
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (e *Engine) reconcileAnnouncing(ctx context.Context, ann store.BGPAnnouncement) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
	if err != nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("lookup_error").Inc()
		return false
	}
	if !conn.Enabled {
		metrics.BGPAnnouncingReconcile.WithLabelValues("skipped_disabled").Inc()
		return false
	}
	sp := bgp.Shared()
	if sp == nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("probe_error").Inc()
		log.Printf("ERROR action: announcing reconcile announcement_id=%d: speaker not configured", ann.ID)
		return false
	}
	if ann.Kind == "flowspec" {
		err = sp.AnnounceFlowspec(ctx, flowspecRuleFromSpec(ann))
	} else {
		err = sp.AnnounceBlackhole(ctx, ann.Prefix)
	}
	if err != nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("probe_error").Inc()
		log.Printf("ERROR action: announcing reconcile announcement_id=%d: %v", ann.ID, err)
		return false
	}
	err = retryBGPStateWrite(func(writeCtx context.Context) error {
		return e.store.BGPAnnouncements().MarkAnnounced(writeCtx, ann.ID, ann.Gen)
	})
	if err == nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("announced").Inc()
		log.Printf("action: announcing label repaired announcement_id=%d gen=%d", ann.ID, ann.Gen)
		return true
	}
	if bgpStateNotApplied(err, ann.ID, ann.Gen, "announced") {
		metrics.BGPAnnouncingReconcile.WithLabelValues("stale").Inc()
		return true
	}
	metrics.BGPAnnouncingReconcile.WithLabelValues("state_write_error").Inc()
	metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
	log.Printf("ERROR action: announcing state write announcement_id=%d: %v", ann.ID, err)
	return false
}
