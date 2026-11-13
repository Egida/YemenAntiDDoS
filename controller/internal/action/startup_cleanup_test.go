package action

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fzWaitStore struct {
	store.Store
	mu       sync.Mutex
	anns     []store.BGPAnnouncement
	detached map[int]bool
	queries  map[int]int
	gate     <-chan struct{}
	finished chan int
}
type fzWaitAnns struct {
	store.BGPAnnouncementRepo
	s *fzWaitStore
}
type fzWaitConns struct {
	store.BGPConnectorRepo
	s *fzWaitStore
}
type fzWaitAttacks struct{ store.AttackRepo }
type fzWaitSchedules struct{ store.ScheduledActionRepo }
type fzWaitRules struct{ store.XDropActiveRuleRepo }

func (s *fzWaitStore) BGPAnnouncements() store.BGPAnnouncementRepo { return fzWaitAnns{s: s} }
func (s *fzWaitStore) BGPConnectors() store.BGPConnectorRepo       { return fzWaitConns{s: s} }
func (s *fzWaitStore) Attacks() store.AttackRepo                   { return fzWaitAttacks{} }
func (s *fzWaitStore) ScheduledActions() store.ScheduledActionRepo { return fzWaitSchedules{} }
func (s *fzWaitStore) XDropActiveRules() store.XDropActiveRuleRepo { return fzWaitRules{} }
func (fzWaitAttacks) LiveIDs(context.Context, []int) (map[int]bool, error) {
	return map[int]bool{}, nil
}
func (fzWaitSchedules) ListPending(context.Context) ([]store.ScheduledAction, error) { return nil, nil }
func (fzWaitSchedules) ListExecuting(context.Context) ([]store.ScheduledAction, error) {
	return nil, nil
}
func (fzWaitRules) ListActive(context.Context) ([]store.XDropActiveRule, error) { return nil, nil }
func (r fzWaitAnns) ListActive(context.Context) ([]store.BGPAnnouncement, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return append([]store.BGPAnnouncement(nil), r.s.anns...), nil
}
func (r fzWaitAnns) Get(_ context.Context, id int) (*store.BGPAnnouncement, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if id < 1 || id > len(r.s.anns) {
		return nil, nil
	}
	ann := r.s.anns[id-1]
	return &ann, nil
}
func (r fzWaitAnns) ListAttacks(_ context.Context, id int) ([]store.BGPAnnouncementAttack, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	row := store.BGPAnnouncementAttack{AnnouncementID: id, AttackID: id}
	if r.s.detached[id] {
		now := time.Now()
		row.DetachedAt = &now
	}
	return []store.BGPAnnouncementAttack{row}, nil
}
func (r fzWaitAnns) ReconcileAttachments(_ context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if !detach || len(ended) != 1 || ended[0] != id {
		return store.BGPReconcileResult{}, fmt.Errorf("unexpected reconciliation: id=%d ended=%v detach=%v", id, ended, detach)
	}
	r.s.detached[id] = true
	r.s.anns[id-1].Refcount, r.s.anns[id-1].Status = 0, "withdrawing"
	return store.BGPReconcileResult{Detached: []int{id}, RefcountBefore: 1, NeedWithdraw: true}, nil
}
func (r fzWaitAnns) setStatus(id int, status string) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.anns[id-1].Status = status
}
func (r fzWaitAnns) MarkWithdrawn(_ context.Context, id int, gen int) error {
	r.setStatus(id, "withdrawn")
	r.s.finished <- id
	return nil
}
func (r fzWaitAnns) MarkFailedWithdraw(_ context.Context, id int, gen int, _ string) error {
	r.setStatus(id, "failed")
	r.s.finished <- id
	return nil
}
func (r fzWaitConns) Get(_ context.Context, id int) (*store.BGPConnector, error) {
	r.s.mu.Lock()
	r.s.queries[id]++
	n, gate := r.s.queries[id], r.s.gate
	r.s.mu.Unlock()
	if n == 2 && gate != nil {
		<-gate
	}
	return &store.BGPConnector{ID: id, Enabled: true, BGPASN: 64512}, nil
}
func fzWaitNew(t *testing.T, n int, gate <-chan struct{}) (*fzWaitStore, *bgp.FakeSpeaker) {
	t.Helper()
	s := &fzWaitStore{detached: map[int]bool{}, queries: map[int]int{}, gate: gate, finished: make(chan int, n)}
	for id := 1; id <= n; id++ {
		s.anns = append(s.anns, store.BGPAnnouncement{ID: id, Prefix: fmt.Sprintf("192.0.2.%d/32", 70+id), RouteMap: "RTBH", ConnectorID: id, Refcount: 1, Status: "active"})
	}
	fake := &bgp.FakeSpeaker{}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })
	return s, fake
}
func (s *fzWaitStore) state(t *testing.T, id int, status string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.anns[id-1]
	if a.Refcount != 0 || a.Status != status || !s.detached[id] {
		t.Errorf("announcement %d: refcount=%d status=%s detached=%t; want 0/%s/true", id, a.Refcount, a.Status, s.detached[id], status)
	}
}
func fzWaitCounter() float64 {
	return testutil.ToFloat64(metrics.StartupCleanup.WithLabelValues("bgp", "dispatched"))
}
func fzWaitLimit(t *testing.T) {
	t.Helper()
	old := cleanupWithdrawWait
	cleanupWithdrawWait = 200 * time.Millisecond
	t.Cleanup(func() { cleanupWithdrawWait = old })
}

func TestFuzhuo_G1_EndedWithdrawal(t *testing.T) {
	fzWaitLimit(t)
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		s, fake := fzWaitNew(t, 1, gate)
		logs, before, start := dao6CaptureLog(t), fzWaitCounter(), time.Now()
		NewEngine(s, "auto").CleanupEndedAttachments(context.Background(), StartupScheduleSnapshot{}, nil)
		if elapsed := time.Since(start); elapsed != 200*time.Millisecond {
			t.Errorf("fake wait=%v want 200ms", elapsed)
		}
		s.state(t, 1, "withdrawing")
		if delta := fzWaitCounter() - before; delta != 1 {
			t.Errorf("dispatched delta=%v want 1", delta)
		}
		if text := logs.text(); strings.Count(text, "WARN") != 1 || !strings.Contains(text, "unfinished=1") {
			t.Errorf("timeout WARN: %s", text)
		}
		if fake.Count("withdraw_blackhole") != 0 {
			t.Errorf("withdraw calls=%d want 0", fake.Count("withdraw_blackhole"))
		}
		close(gate)
		synctest.Wait()
		s.state(t, 1, "withdrawn")
		if fake.Count("withdraw_blackhole") != 1 {
			t.Errorf("withdraw calls=%d want 1", fake.Count("withdraw_blackhole"))
		}
	})
}

func TestFuzhuo_G10_AsyncWithdrawDoesNotBlockStartup(t *testing.T) {
	fzWaitLimit(t)
	s, fake := fzWaitNew(t, 2, nil)
	logs, before := dao6CaptureLog(t), fzWaitCounter()
	done := make(chan struct{})
	go func() {
		NewEngine(s, "auto").CleanupEndedAttachments(context.Background(), StartupScheduleSnapshot{}, nil)
		close(done)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case <-done:
	case <-deadline.C:
		t.Fatal("CleanupEndedAttachments waited for blocked speaker withdrawal (5s deadline)")
	}
	if delta := fzWaitCounter() - before; delta != 2 {
		t.Errorf("dispatched delta=%v want 2", delta)
	}
	if text := logs.text(); strings.Contains(text, "startup cleanup BGP withdrawal wait expired") {
		t.Errorf("unexpected startup withdrawal timeout: %s", text)
	}
	for range 2 {
		select {
		case <-s.finished:
		case <-deadline.C:
			t.Fatal("withdrawal did not finish")
		}
	}
	s.state(t, 1, "withdrawn")
	s.state(t, 2, "withdrawn")
	if fake.Count("withdraw_blackhole") != 2 {
		t.Errorf("withdraw calls=%d want 2", fake.Count("withdraw_blackhole"))
	}
}
