package tests

// helpers_test.go — shared test infrastructure for the tests package.
// Defines the JWT constant, token generator, and base router constructor
// that every test file in this package relies on.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// testJWTSecret is the shared JWT signing secret used across all test files.
const testJWTSecret = "test-secret-key"

var testUserUpdatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// makeTestToken generates a valid HS256 JWT signed with testJWTSecret.
// Used to add an Authorization header to test HTTP requests.
func makeTestToken(t *testing.T) string {
	t.Helper()
	type claims struct {
		UserID   int    `json:"user_id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Rev      int64  `json:"rev"`
		jwt.RegisteredClaims
	}
	c := claims{
		UserID:   1,
		Username: "testuser",
		Role:     "admin",
		Rev:      testUserUpdatedAt.UnixMicro(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("makeTestToken: %v", err)
	}
	return signed
}

// setupRouter builds a gin.Engine backed by the given store with no optional
// dependencies (ConfigPub=nil, ActionEngine=nil). Used by tests that only
// exercise pure CRUD / response-action logic.
func setupRouter(s store.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	deps := api.Dependencies{
		Store:     s,
		JWTSecret: testJWTSecret,
		APIKey:    "test-api-key",
	}
	return api.NewRouter(deps)
}

// intPtr returns a pointer to an int. Convenience helper for test fixtures.
func intPtr(i int) *int { return &i }

type dao5LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao5LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *dao5LogBuffer) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

func dao5CaptureLog(t *testing.T) *dao5LogBuffer {
	t.Helper()
	b := &dao5LogBuffer{}
	old := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}

// daoInstallSpeaker installs a fake embedded speaker for one test.
func daoInstallSpeaker(t *testing.T) *bgp.FakeSpeaker {
	t.Helper()
	fake := &bgp.FakeSpeaker{}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })
	return fake
}

func dao13dAwait(t *testing.T, limit time.Duration, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-timer.C:
			t.Fatal("required observation did not arrive before deadline")
		case <-tick.C:
		}
	}
}

func doGet(t *testing.T, r *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)
	return w
}

func doPost(t *testing.T, r *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	dao5bCheck(t, err)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// ip returns a pointer to an int. Used in tests where ActionID needs an int pointer.
func ip(i int) *int {
	v := i
	return &v
}

func dao5bCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func dao5bRow(t *testing.T, r store.BGPAnnouncementRepo, id int) *store.BGPAnnouncement {
	t.Helper()
	a, err := r.Get(context.Background(), id)
	if err != nil || a == nil {
		t.Fatalf("Get(%d)=%+v err=%v", id, a, err)
	}
	return a
}

func dao5bCurrentGen(t *testing.T, r store.BGPAnnouncementRepo, id int) int {
	t.Helper()
	return dao5bRow(t, r, id).Gen
}

type dao4Rules struct {
	store.XDropActiveRuleRepo
	mu              sync.Mutex
	marks           []string
	listErr         error
	nextMarkErr     error
	beforeMark      func()
	beforeWithdrawn func()
}

func (r *dao4Rules) MarkWithdrawn(ctx context.Context, a, b, c int, rule string) error {
	r.mu.Lock()
	before := r.beforeWithdrawn
	r.mu.Unlock()
	if before != nil {
		before()
	}
	return r.XDropActiveRuleRepo.MarkWithdrawn(ctx, a, b, c, rule)
}

func (r *dao4Rules) ListByAttack(ctx context.Context, a int) ([]store.XDropActiveRule, error) {
	r.mu.Lock()
	err := r.listErr
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return r.XDropActiveRuleRepo.ListByAttack(ctx, a)
}
func (r *dao4Rules) MarkWithdrawing(ctx context.Context, a, b, c int, rule string) (bool, error) {
	r.mu.Lock()
	r.marks = append(r.marks, fmt.Sprintf("%d/%d/%d/%s", a, b, c, rule))
	before := r.beforeMark
	err := r.nextMarkErr
	r.nextMarkErr = nil
	r.mu.Unlock()
	if before != nil {
		before()
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
func (r *dao4Rules) markCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.marks)
}

func dao4SeedRule(t *testing.T, ms *MockStore, status, rule string, withLog bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := ms.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: rule, Status: status}); err != nil {
		t.Fatal(err)
	}
	if withLog {
		status := "success"
		if strings.HasPrefix(rule, "failed-create-") {
			status = "failed"
		}
		if _, err := ms.ActionExecLog().Create(ctx, &store.ActionExecutionLog{AttackID: 20, ActionID: 10, ActionType: "xdrop", TriggerPhase: "on_detected", Status: status, ConnectorID: intPtr(7), ExternalRuleID: rule, ExecutedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
}

type dao4RuleStore struct {
	*MockStore
	rules store.XDropActiveRuleRepo
}

func (s dao4RuleStore) XDropActiveRules() store.XDropActiveRuleRepo { return s.rules }

type dao4Transport struct {
	mu       sync.Mutex
	requests []*http.Request
	status   int
	handler  func(*http.Request) int
}

func (d *dao4Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, r.Clone(r.Context()))
	status := d.status
	d.mu.Unlock()
	if d.handler != nil {
		status = d.handler(r)
	}
	if status == 0 {
		status = http.StatusOK
		if r.Method == "DELETE" {
			status = http.StatusNoContent
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
}

func (d *dao4Transport) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.requests)
}

func dao4HTTP(t *testing.T) *dao4Transport {
	d := &dao4Transport{}
	oldDefault, oldWebhook := http.DefaultTransport, action.WebhookTransport
	http.DefaultTransport, action.WebhookTransport = d, d
	if t != nil {
		t.Cleanup(func() {
			http.DefaultTransport, action.WebhookTransport = oldDefault, oldWebhook
		})
	}
	return d
}

func dao4Fixture(kind, mode, phase string) (*MockStore, *action.Engine, tracker.AttackEvent) {
	ms := NewMockStore()
	ms.responses.responses = []store.Response{{ID: 1, Name: "dao4", Enabled: true}}
	ms.responses.actions = []store.ResponseAction{{ID: 10, ResponseID: 1, ActionType: kind, TriggerPhase: phase, RunMode: mode, Enabled: true, Execution: "automatic", Config: []byte(`{"url":"http://dao4.invalid/webhook"}`), XDropAction: "drop"}}
	return ms, action.NewEngine(ms, "auto"), tracker.AttackEvent{Type: "confirmed", DBID: 20, Attack: &store.Attack{ID: 20, ResponseID: intPtr(1), DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", AttackType: "udp_flood", PeakPPS: 100, StartedAt: time.Now()}}
}

func dao4XDrop() (*MockStore, *dao4Rules, *action.Engine, tracker.AttackEvent) {
	ms, _, ev := dao4Fixture("xdrop", "once", "on_detected")
	ms.responses.actions[0].Config = nil
	ms.responses.actions = append(ms.responses.actions, store.ResponseAction{ID: 11, ResponseID: 1, ActionType: "xdrop", TriggerPhase: "on_expired", RunMode: "once", XDropAction: "unblock", Enabled: true})
	ms.xdropConnectors.connectors = []store.XDropConnector{{ID: 7, Name: "dao4", APIURL: "http://dao4.invalid", Enabled: true}}
	r := &dao4Rules{XDropActiveRuleRepo: ms.XDropActiveRules()}
	return ms, r, action.NewEngine(dao4RuleStore{ms, r}, "auto"), ev
}

type dao5BGPAnnouncements struct {
	store.BGPAnnouncementRepo
	mu                        sync.Mutex
	failWithdrawn, failFailed int
	onFailure                 func()
}

func (r *dao5BGPAnnouncements) inject(withdrawn, failed int, hook func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failWithdrawn, r.failFailed, r.onFailure = withdrawn, failed, hook
}

func (r *dao5BGPAnnouncements) stateWrite(ctx context.Context, failed bool, id, gen int, msg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (r *dao5BGPAnnouncements) MarkWithdrawn(ctx context.Context, id, gen int) error {
	r.mu.Lock()
	fail := r.failWithdrawn > 0
	if fail {
		r.failWithdrawn--
	}
	hook := r.onFailure
	r.mu.Unlock()
	if fail {
		if hook != nil {
			hook()
		}
		return errors.New("dao5b force withdraw fail")
	}
	return r.BGPAnnouncementRepo.MarkWithdrawn(ctx, id, gen)
}

func (r *dao5BGPAnnouncements) MarkFailedWithdraw(ctx context.Context, id, gen int, msg string) error {
	r.mu.Lock()
	fail := r.failFailed > 0
	if fail {
		r.failFailed--
	}
	hook := r.onFailure
	r.mu.Unlock()
	if fail {
		if hook != nil {
			hook()
		}
		return errors.New("dao5b force fail")
	}
	return r.BGPAnnouncementRepo.MarkFailedWithdraw(ctx, id, gen, msg)
}

type dao5BGPStore struct {
	*MockStore
	mu    sync.Mutex
	anns  *dao5BGPAnnouncements
	sched store.ScheduledActionRepo
}

func (s *dao5BGPStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s *dao5BGPStore) ScheduledActions() store.ScheduledActionRepo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sched != nil {
		return s.sched
	}
	return s.MockStore.ScheduledActions()
}

func dao5BGPFixture(t *testing.T, delay int) (*dao5BGPStore, *action.Engine, tracker.AttackEvent, *store.BGPConnector, int) {
	t.Helper()
	ms, _, ev := dao4Fixture("bgp", "once", "on_expired")
	fake := daoInstallSpeaker(t)
	_ = fake
	ms.responses.actions[0].BGPConnectorID = intPtr(7)
	ms.responses.actions[0].BGPRouteMap = "RTBH"
	conn := &store.BGPConnector{ID: 7, Name: "dao5", Enabled: true, NeighborIP: "192.0.2.1", NeighborASN: 65001, BGPASN: 64512}
	ms.bgpConnectors.connectors = []store.BGPConnector{*conn}
	s := &dao5BGPStore{MockStore: ms, anns: &dao5BGPAnnouncements{BGPAnnouncementRepo: ms.BGPAnnouncements()}}
	result, err := s.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 20, ActionID: intPtr(10), DelayMinutes: delay})
	dao5bCheck(t, err)
	if err := s.BGPAnnouncements().MarkAnnounced(context.Background(), result.AnnouncementID, dao5bCurrentGen(t, s.BGPAnnouncements(), result.AnnouncementID)); err != nil {
		t.Fatal(err)
	}
	ev.Type = "expired"
	return s, action.NewEngine(s, "auto"), ev, conn, result.AnnouncementID
}

func decodeList(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var items []map[string]any
	dao5bCheck(t, json.Unmarshal(w.Body.Bytes(), &items))
	return items
}
