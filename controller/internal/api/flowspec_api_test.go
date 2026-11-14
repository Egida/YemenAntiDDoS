package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

type bgpFlowspecAnnouncements struct {
	store.BGPAnnouncementRepo
	mu         sync.Mutex
	row        store.BGPAnnouncement
	forceCalls int
}

func (r *bgpFlowspecAnnouncements) Get(context.Context, int) (*store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.row
	return &row, nil
}

func (r *bgpFlowspecAnnouncements) ForceWithdraw(_ context.Context, id int) ([]store.BGPAnnouncementAttack, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forceCalls++
	r.row.Gen++
	r.row.Status = "withdrawing"
	return nil, r.row.Gen, nil
}

func (r *bgpFlowspecAnnouncements) MarkWithdrawn(_ context.Context, id, gen int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.row.Status = "withdrawn"
	return nil
}

func (r *bgpFlowspecAnnouncements) MarkFailedWithdraw(_ context.Context, id, gen int, message string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.row.Status = "failed"
	r.row.ErrorMessage = message
	return nil
}

type bgpFlowspecStore struct {
	*dao11cStore
	announcements *bgpFlowspecAnnouncements
}

func (s *bgpFlowspecStore) BGPAnnouncements() store.BGPAnnouncementRepo {
	return s.announcements
}

func bgpFlowspecRequest(t *testing.T, deps Dependencies, id string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(http.MethodPost, "/api/flowspec/announcements/"+id+"/force-withdraw", nil)
	forceWithdrawFlowspec(deps)(c)
	return w
}

func TestBGPFlowspecForceWithdrawSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &bgpFlowspecAnnouncements{row: store.BGPAnnouncement{
		ID: 1, Prefix: "192.0.2.10/32", RouteMap: "xsight-flow", Kind: "flowspec", Status: "active", Gen: 3,
		RuleSpec: `{"Name":"xsight-flow","Prefix":"192.0.2.10/32","Action":"drop"}`,
	}}
	s := &bgpFlowspecStore{dao11cStore: dao11cFixture(), announcements: repo}
	fake := &bgp.FakeSpeaker{}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })

	w := bgpFlowspecRequest(t, Dependencies{Store: s}, "1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if fake.Count("withdraw_flowspec") != 1 || len(fake.Rules) != 1 {
		t.Fatalf("speaker withdrawals = %d rules=%d", fake.Count("withdraw_flowspec"), len(fake.Rules))
	}
	if fake.Rules[0].Name != "xsight-flow" || fake.Rules[0].Prefix != "192.0.2.10/32" {
		t.Fatalf("withdrawn rule = %+v", fake.Rules[0])
	}
	if repo.row.Status != "withdrawn" || repo.forceCalls != 1 {
		t.Fatalf("announcement status=%q forceCalls=%d", repo.row.Status, repo.forceCalls)
	}
}

func TestBGPFlowspecForceWithdrawEmptyRuleSpecUsesFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &bgpFlowspecAnnouncements{row: store.BGPAnnouncement{
		ID: 1, Prefix: "192.0.2.10/32", RouteMap: "xsight-flow", Kind: "flowspec", Status: "active", Gen: 3,
	}}
	s := &bgpFlowspecStore{dao11cStore: dao11cFixture(), announcements: repo}
	fake := &bgp.FakeSpeaker{}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })

	w := bgpFlowspecRequest(t, Dependencies{Store: s}, "1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if len(fake.Rules) != 1 || fake.Rules[0].Name != "xsight-flow" || fake.Rules[0].Prefix != "192.0.2.10/32" || fake.Rules[0].Action != "drop" {
		t.Fatalf("fallback withdrawal rules = %+v", fake.Rules)
	}
}

func TestBGPFlowspecForceWithdrawMalformedRuleFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, ruleSpec string
	}{
		{"malformed_json", `{not-json`},
		{"invalid_rule", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &bgpFlowspecAnnouncements{row: store.BGPAnnouncement{
				ID: 1, Prefix: "192.0.2.10/32", RouteMap: "xsight-flow", Kind: "flowspec", Status: "active", Gen: 3,
				RuleSpec: tc.ruleSpec,
			}}
			s := &bgpFlowspecStore{dao11cStore: dao11cFixture(), announcements: repo}
			fake := &bgp.FakeSpeaker{}
			bgp.SetShared(fake)
			t.Cleanup(func() { bgp.SetShared(nil) })

			w := bgpFlowspecRequest(t, Dependencies{Store: s}, "1")
			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
			}
			if repo.forceCalls != 0 || repo.row.Status != "active" || repo.row.Gen != 3 {
				t.Fatalf("failed request mutated announcement: status=%q gen=%d forceCalls=%d", repo.row.Status, repo.row.Gen, repo.forceCalls)
			}
			if fake.Count("withdraw_flowspec") != 0 {
				t.Fatal("failed request withdrew a reconstructed fallback rule")
			}
		})
	}
}
