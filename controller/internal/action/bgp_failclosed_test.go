package action

import (
	"context"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// ForceRemove on a flowspec connector without an announcement row cannot
// reconstruct the flowspec key, so it must fail closed instead of withdrawing
// a blackhole path that was never installed.
func TestForceRemoveBGPFlowspecWithoutAnnouncementFailsClosed(t *testing.T) {
	s, _, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	s.conn.FlowspecEnabled = true

	err := NewEngine(s, "auto").ForceRemove(context.Background(), 20, 10, 7, "198.51.100.7/32|xsight-flow")
	if err == nil {
		t.Fatal("ForceRemove: want error for flowspec connector without announcement row")
	}
	if !strings.Contains(err.Error(), "flowspec") {
		t.Errorf("error %q should explain the flowspec rule cannot be reconstructed", err)
	}
	if fake.Count("withdraw_blackhole") != 0 || fake.Count("withdraw_flowspec") != 0 {
		t.Errorf("speaker withdrawals: blackhole=%d flowspec=%d want 0/0",
			fake.Count("withdraw_blackhole"), fake.Count("withdraw_flowspec"))
	}
}

// The RTBH fallback is preserved for non-flowspec connectors.
func TestForceRemoveBGPRTBHWithoutAnnouncementWithdrawsBlackhole(t *testing.T) {
	s, _, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)

	if err := NewEngine(s, "auto").ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH"); err != nil {
		t.Fatalf("ForceRemove: %v", err)
	}
	if fake.Count("withdraw_blackhole") != 1 {
		t.Errorf("withdraw_blackhole=%d want 1", fake.Count("withdraw_blackhole"))
	}
}

// A malformed rule_spec must never be announced as a broadened
// destination-only rule; the row stays in "announcing" for a later retry.
func TestRetryBGPAnnounceMalformedRuleSpecFailsClosed(t *testing.T) {
	s, _, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	ann := store.BGPAnnouncement{
		ID: 1, Prefix: "198.51.100.7/32", RouteMap: "xsight-flow", ConnectorID: 7,
		Status: "announcing", Kind: "flowspec", RuleSpec: "{not-json",
	}

	NewEngine(s, "auto").retryBGPAnnounce(ann)

	if fake.Count("announce_flowspec") != 0 || fake.Count("announce_blackhole") != 0 {
		t.Errorf("announcements: flowspec=%d blackhole=%d want 0/0",
			fake.Count("announce_flowspec"), fake.Count("announce_blackhole"))
	}
}

// A malformed rule_spec must not be withdrawn as a broadened rule: the
// withdraw fails closed and the announcement is marked failed.
func TestPerformBGPWithdrawMalformedRuleSpecFailsClosed(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	s.ann.rows = []store.BGPAnnouncement{
		{ID: 1, Prefix: "198.51.100.7/32", RouteMap: "xsight-flow", ConnectorID: 7,
			Status: "withdrawing", Kind: "flowspec", RuleSpec: "{not-json"},
	}
	conn := s.conn

	log, err := performBGPWithdraw(context.Background(), s, &conn, act, "198.51.100.7/32", "xsight-flow", 20, 1, 0, "test", "on_expired")
	if err == nil {
		t.Fatal("performBGPWithdraw: want error for malformed rule_spec")
	}
	if log == nil || log.Status != "failed" {
		t.Fatalf("log=%+v want failed status", log)
	}
	if fake.Count("withdraw_flowspec") != 0 || fake.Count("withdraw_blackhole") != 0 {
		t.Errorf("withdrawals: flowspec=%d blackhole=%d want 0/0",
			fake.Count("withdraw_flowspec"), fake.Count("withdraw_blackhole"))
	}
}

// The announcing reconcile must report a probe error for a malformed
// rule_spec instead of announcing a broadened rule.
func TestReconcileAnnouncingMalformedRuleSpecFailsClosed(t *testing.T) {
	s, _, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)

	got := NewEngine(s, "auto").reconcileAnnouncing(context.Background(), store.BGPAnnouncement{
		ID: 1, ConnectorID: 7, Prefix: "198.51.100.7/32", RouteMap: "xsight-flow",
		Kind: "flowspec", RuleSpec: "{not-json",
	})
	if got {
		t.Error("reconcileAnnouncing: want false for malformed rule_spec")
	}
	if fake.Count("announce_flowspec") != 0 || fake.Count("announce_blackhole") != 0 {
		t.Errorf("announcements: flowspec=%d blackhole=%d want 0/0",
			fake.Count("announce_flowspec"), fake.Count("announce_blackhole"))
	}
}

// Recovery skips a row with a malformed rule_spec and continues with the
// remaining rows.
func TestRecoverBGPRoutesMalformedRuleSpecSkipsRow(t *testing.T) {
	s, _, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	s.ann.rows = []store.BGPAnnouncement{
		{ID: 1, Prefix: "198.51.100.7/32", RouteMap: "xsight-flow", ConnectorID: 7,
			Status: "active", Kind: "flowspec", RuleSpec: "{not-json"},
		{ID: 2, Prefix: "203.0.113.9/32", RouteMap: "xsight-flow", ConnectorID: 7,
			Status: "active", Kind: "flowspec",
			RuleSpec: `{"Name":"xsight-flow","Prefix":"203.0.113.9/32","Protocol":6,"Action":"drop"}`},
	}

	RecoverBGPRoutes(context.Background(), s)

	if fake.Count("announce_flowspec") != 1 {
		t.Errorf("announce_flowspec=%d want 1 (only the well-formed row)", fake.Count("announce_flowspec"))
	}
	if len(fake.Rules) != 1 || fake.Rules[0].Prefix != "203.0.113.9/32" {
		t.Errorf("announced rules=%+v want only the well-formed rule", fake.Rules)
	}
}

// An empty rule_spec is the legitimate fallback case: it must not be treated
// as malformed, so the withdrawal still runs.
func TestPerformBGPWithdrawEmptyRuleSpecUsesFallbackRule(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	s.ann.rows = []store.BGPAnnouncement{
		{ID: 1, Prefix: "198.51.100.7/32", RouteMap: "xsight-flow", ConnectorID: 7,
			Status: "withdrawing", Kind: "flowspec", RuleSpec: ""},
	}
	conn := s.conn

	log, err := performBGPWithdraw(context.Background(), s, &conn, act, "198.51.100.7/32", "xsight-flow", 20, 1, 0, "test", "on_expired")
	if err != nil || log == nil || log.Status != "success" {
		t.Fatalf("withdraw log=%+v err=%v want success", log, err)
	}
	if fake.Count("withdraw_flowspec") != 1 {
		t.Errorf("withdraw_flowspec=%d want 1", fake.Count("withdraw_flowspec"))
	}
}

// The flowspec withdraw path must fail closed on a malformed rule_spec: no
// broadened withdrawal is sent to the speaker.
func TestFlowspecWithdrawMalformedRuleSpecFailsClosed(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	ruleName := flowspecRuleName("198.51.100.7/32")
	s.ann.rows = []store.BGPAnnouncement{
		{ID: 1, Prefix: "198.51.100.7/32", RouteMap: ruleName, ConnectorID: 7,
			Status: "active", Kind: "flowspec", RuleSpec: "{not-json"},
	}
	conn := s.conn

	log, err := flowspecWithdraw(context.Background(), s, &conn, act, "198.51.100.7/32", 20, "test", "on_expired")
	if err == nil {
		t.Fatal("flowspecWithdraw: want error for malformed rule_spec")
	}
	if log == nil || log.Status != "failed" {
		t.Fatalf("log=%+v want failed status", log)
	}
	if fake.Count("withdraw_flowspec") != 0 || fake.Count("withdraw_blackhole") != 0 {
		t.Errorf("withdrawals: flowspec=%d blackhole=%d want 0/0",
			fake.Count("withdraw_flowspec"), fake.Count("withdraw_blackhole"))
	}
}
