package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type dao12hContractStore struct {
	*dao3BGPStore
	connectors    store.BGPConnectorRepo
	announcements store.BGPAnnouncementRepo
}

func (s dao12hContractStore) BGPConnectors() store.BGPConnectorRepo       { return s.connectors }
func (s dao12hContractStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.announcements }

type dao12hContextConnector struct {
	store.BGPConnectorRepo
	received           context.Context
	errAtGet           error
	calledAt, deadline time.Time
	hasDeadline        bool
}

func (r *dao12hContextConnector) Get(ctx context.Context, _ int) (*store.BGPConnector, error) {
	r.received, r.calledAt, r.errAtGet = ctx, time.Now(), ctx.Err()
	r.deadline, r.hasDeadline = ctx.Deadline()
	return nil, errors.New("contract connector lookup failure")
}

type dao12hStaleAnnouncement struct{ store.BGPAnnouncementRepo }

func (dao12hStaleAnnouncement) MarkAnnounced(context.Context, int, int) error {
	return store.ErrStaleAnnouncement
}

func TestDao12h_C1_IndependentContext(t *testing.T) {
	base, _, _ := dao3BGPFixture(t)
	conn := &dao12hContextConnector{BGPConnectorRepo: base.BGPConnectors()}
	s := dao12hContractStore{base, conn, base.BGPAnnouncements()}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	got := NewEngine(s, "auto").reconcileAnnouncing(parent, store.BGPAnnouncement{ID: 1, ConnectorID: 7})
	dao12bWant(t, "C1.CtxNotCanceled", conn.received != nil && conn.errAtGet == nil, conn.errAtGet)
	budget := conn.deadline.Sub(conn.calledAt)
	dao12bWant(t, "C1.Deadline30s", conn.hasDeadline && budget > 29*time.Second && budget <= 30*time.Second, budget)
	dao12bWant(t, "C1.ReturnsFalse", !got, got)
}

func TestDao12h_C2_StaleReturnsTrue(t *testing.T) {
	base, _, _ := dao3BGPFixture(t)
	fake := &bgp.FakeSpeaker{}
	bgp.SetShared(fake)
	s := dao12hContractStore{base, base.BGPConnectors(), dao12hStaleAnnouncement{base.BGPAnnouncements()}}
	counter := func(outcome string) float64 {
		return testutil.ToFloat64(metrics.BGPAnnouncingReconcile.WithLabelValues(outcome))
	}
	stale, failed := counter("stale"), counter("state_write_error")
	got := NewEngine(s, "auto").reconcileAnnouncing(context.Background(), store.BGPAnnouncement{ID: 1, ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"})
	dao12bWant(t, "C2.ReturnsTrue", got, got)
	dao12bWant(t, "C2.StaleDelta", counter("stale")-stale == 1, counter("stale")-stale)
	dao12bWant(t, "C2.NoStateWriteError", counter("state_write_error")-failed == 0, counter("state_write_error")-failed)
	dao12bWant(t, "C2.Reannounced", fake.Count("announce_blackhole") == 1, fake.Count("announce_blackhole"))
}
