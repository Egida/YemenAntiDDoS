package action

import (
	"context"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestFlowspecRuleNameIsStableAndSafe(t *testing.T) {
	cases := map[string]string{
		"198.51.100.7/32": "xsight-198-51-100-7-32",
		"2001:db8::1/128": "xsight-2001-db8--1-128",
		"203.0.113.9":     "xsight-203-0-113-9",
	}
	for in, want := range cases {
		if got := flowspecRuleName(in); got != want {
			t.Errorf("flowspecRuleName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProtocolForDecoder(t *testing.T) {
	cases := []struct {
		family string
		want   uint8
		any    bool
	}{
		{"tcp_syn", 6, true},
		{"http_flood", 6, true},
		{"slowloris", 6, true},
		{"udp_flood", 17, true},
		{"dns_query", 17, true},
		{"icmp_flood", 1, true},
		{"unknown_family", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		got := protocolForDecoder(tc.family)
		if tc.any {
			if got == nil || *got != tc.want {
				t.Errorf("protocolForDecoder(%q) = %v, want %d", tc.family, got, tc.want)
			}
			continue
		}
		if got != nil {
			t.Errorf("protocolForDecoder(%q) = %d, want nil", tc.family, *got)
		}
	}
}

func TestFlowspecRuleForNarrowsMatch(t *testing.T) {
	rule := flowspecRuleFor("198.51.100.7/32", &store.Attack{DecoderFamily: "tcp_syn"})
	if rule.Name != "xsight-198-51-100-7-32" || rule.Prefix != "198.51.100.7/32" {
		t.Fatalf("unexpected rule identity: %+v", rule)
	}
	if rule.Protocol == nil || *rule.Protocol != 6 {
		t.Fatalf("protocol not derived from decoder: %+v", rule.Protocol)
	}
	if rule.Action != flowspec.ActionDrop {
		t.Fatalf("action = %q, want drop", rule.Action)
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("generated rule must validate: %v", err)
	}
}

func TestFlowspecExecutionUsesSpeaker(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	conn := s.conn
	conn.FlowspecEnabled = true
	prefix := "198.51.100.7/32"
	attack := &store.Attack{DstIP: prefix, DecoderFamily: "tcp_syn"}

	log, err := executeBGPFlowspec(context.Background(), s, &conn, act, attack, prefix, 20, "test", "on_detected")
	if err != nil || log == nil || log.Status != "success" {
		t.Fatalf("announce log=%+v err=%v", log, err)
	}
	if fake.Count("announce_flowspec") != 1 || len(fake.Rules) != 1 {
		t.Fatalf("announce calls=%d rules=%d", fake.Count("announce_flowspec"), len(fake.Rules))
	}
	if got := fake.Rules[0].Prefix; got != prefix {
		t.Fatalf("announced prefix=%q want %q", got, prefix)
	}
	wantBody := "destination 198.51.100.7/32, protocol tcp, drop (traffic-rate 0)"
	if log.RequestBody != wantBody {
		t.Fatalf("request body=%q want %q", log.RequestBody, wantBody)
	}

	log, err = executeBGPFlowspec(context.Background(), s, &conn, act, nil, prefix, 20, "test", "on_expired")
	if err != nil || log == nil || log.Status != "success" {
		t.Fatalf("withdraw log=%+v err=%v", log, err)
	}
	if fake.Count("withdraw_flowspec") != 1 {
		t.Fatalf("withdraw calls=%d want 1", fake.Count("withdraw_flowspec"))
	}
}

func TestFlowspecWithdrawUsesAnnouncedRule(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	conn := s.conn
	conn.FlowspecEnabled = true
	prefix := "198.51.100.7/32"
	attack := &store.Attack{DstIP: prefix, DecoderFamily: "tcp_syn"}

	if _, err := executeBGPFlowspec(context.Background(), s, &conn, act, attack, prefix, 20, "test", "on_detected"); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if _, err := executeBGPFlowspec(context.Background(), s, &conn, act, nil, prefix, 20, "test", "on_expired"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(fake.Rules) != 2 {
		t.Fatalf("rules=%d want 2", len(fake.Rules))
	}
	withdrawn := fake.Rules[1]
	if withdrawn.Protocol == nil || *withdrawn.Protocol != 6 {
		t.Fatalf("withdrawn rule protocol=%v want 6", withdrawn.Protocol)
	}
	if withdrawn.Prefix != prefix || withdrawn.Name != fake.Rules[0].Name {
		t.Fatalf("withdrawn rule identity=%+v", withdrawn)
	}
}

func TestRTBHExecutionUsesSpeaker(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	prefix := "192.0.2.10/32"
	attack := &store.Attack{DstIP: "192.0.2.10"}

	log, err := executeBGP(context.Background(), s, nil, act, attack, "detected", prefix, "test", "on_detected", 20, nil)
	if err != nil || log == nil || log.Status != "success" {
		t.Fatalf("announce log=%+v err=%v", log, err)
	}
	if fake.Count("announce_blackhole") != 1 || len(fake.Prefixes) != 1 || fake.Prefixes[0] != prefix {
		t.Fatalf("announce calls=%d prefixes=%v", fake.Count("announce_blackhole"), fake.Prefixes)
	}
}

func TestExecuteBGPWithoutSpeakerSkips(t *testing.T) {
	s, act, _ := dao3BGPFixture(t)
	bgp.SetShared(nil)
	attack := &store.Attack{DstIP: "192.0.2.10"}
	log, err := executeBGP(context.Background(), s, nil, act, attack, "detected", "192.0.2.10", "test", "on_detected", 20, nil)
	if err != nil || log == nil {
		t.Fatalf("log=%+v err=%v", log, err)
	}
	if log.Status != "skipped" || log.SkipReason != SkipReasonSpeakerNotConfigured {
		t.Fatalf("status=%q skip_reason=%q", log.Status, log.SkipReason)
	}
}

func TestRecoverBGPRoutesRestoresSpeakerPaths(t *testing.T) {
	s, _, _ := dao3BGPFixture(t)
	fake := bgp.Shared().(*bgp.FakeSpeaker)
	s.ann.rows = []store.BGPAnnouncement{
		{ID: 1, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, Status: "active"},
		{ID: 2, Prefix: "198.51.100.0/24", RouteMap: "xsight-flow", ConnectorID: 7, Status: "delayed", Kind: "flowspec", RuleSpec: `{"Name":"xsight-flow","Prefix":"198.51.100.0/24","Action":"drop"}`},
	}

	RecoverBGPRoutes(context.Background(), s)
	if fake.Count("announce_blackhole") != 1 || fake.Count("announce_flowspec") != 1 {
		t.Fatalf("announce calls=%d flowspec calls=%d", fake.Count("announce_blackhole"), fake.Count("announce_flowspec"))
	}
}
