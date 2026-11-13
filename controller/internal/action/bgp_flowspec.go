package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// flowspecRuleName derives the stable rule identifier for a destination
// prefix. It must be deterministic so that two attacks against the same
// prefix share one announcement (refcounted) instead of fighting over the
// rule, and so that withdraw can rebuild the rule from the announcement.
func flowspecRuleName(prefix string) string {
	var b strings.Builder
	b.WriteString("xsight-")
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// protocolForDecoder maps the attack's decoder family to an IP protocol
// number so the Flowspec match stays as narrow as the detector allows.
// Returning nil omits the protocol match (whole-destination rule).
func protocolForDecoder(family string) *uint8 {
	f := strings.ToLower(family)
	tcp, udp, icmp := uint8(6), uint8(17), uint8(1)
	switch {
	case strings.Contains(f, "tcp"), strings.Contains(f, "syn"), strings.Contains(f, "http"),
		strings.Contains(f, "slowloris"), strings.Contains(f, "tls"):
		return &tcp
	case strings.Contains(f, "udp"), strings.Contains(f, "dns"), strings.Contains(f, "ntp"),
		strings.Contains(f, "ssdp"), strings.Contains(f, "memcached"), strings.Contains(f, "chargen"),
		strings.Contains(f, "snmp"), strings.Contains(f, "quic"):
		return &udp
	case strings.Contains(f, "icmp"):
		return &icmp
	default:
		return nil
	}
}

func flowspecRuleFor(dstIP string, attack *store.Attack) flowspec.Rule {
	r := flowspec.Rule{
		Name:   flowspecRuleName(dstIP),
		Prefix: dstIP,
		Action: flowspec.ActionDrop,
	}
	if attack != nil {
		r.Protocol = protocolForDecoder(attack.DecoderFamily)
	}
	return r
}

// executeBGPFlowspec is the Flowspec counterpart of bgpAnnounce/bgpWithdraw.
// It shares the refcounted announcement lifecycle with RTBH but stores
// Kind="flowspec" plus the rule so the console can inspect and force-withdraw it.
func executeBGPFlowspec(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	attack *store.Attack, dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	switch triggerPhase {
	case "on_detected":
		return flowspecAnnounce(ctx, s, conn, act, attack, dstIP, attackDBID, responseName, triggerPhase)
	case "on_expired":
		return flowspecWithdraw(ctx, s, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	default:
		return recordSkip(&store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "skipped",
			ErrorMessage: fmt.Sprintf("unknown trigger_phase: %s", triggerPhase),
			ExecutedAt:   time.Now(),
		}, SkipReasonUnknownTriggerPhase), nil
	}
}

func flowspecAnnounce(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	attack *store.Attack, dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	rule := flowspecRuleFor(dstIP, attack)
	ruleJSON, _ := json.Marshal(rule)
	externalRuleID := fmt.Sprintf("%s|%s", rule.Prefix, rule.Name)
	actID := act.ID
	connID := conn.ID

	if overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); err != nil {
		log.Printf("action: flowspec announce override lookup: %v", err)
	} else if overridden {
		logCtx, cancel := execLogContext()
		writeSkipLog(logCtx, s, attackDBID, act, responseName, conn.Name, SkipReasonManualOverride, "")
		cancel()
		return nil, nil
	}

	attachResult, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID:     attackDBID,
		ActionID:     &actID,
		ResponseName: responseName,
		DelayMinutes: 0,
		Prefix:       rule.Prefix,
		RouteMap:     rule.Name,
		ConnectorID:  connID,
		Kind:         "flowspec",
		RuleSpec:     string(ruleJSON),
	})
	if err != nil {
		log.Printf("action: flowspec attach failed attack=%d prefix=%s: %v", attackDBID, rule.Prefix, err)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("attach: %v", err),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	if !attachResult.NeedAnnounce {
		detail := fmt.Sprintf("attached to flowspec announcement_id=%d (shared)", attachResult.AnnouncementID)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         detail,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	sp := bgp.Shared()
	if sp == nil {
		msg := "bgp speaker not configured: set up Settings → BGP Instance first"
		markAnnounceFailed(ctx, s, attachResult, errors.New(msg))
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed", ErrorMessage: msg,
			ExternalRuleID: externalRuleID, ExecutedAt: time.Now(),
		}, errors.New(msg)
	}

	t0 := time.Now()
	aErr := sp.AnnounceFlowspec(ctx, rule)
	durationMs := int(time.Since(t0).Milliseconds())
	if aErr != nil {
		markAnnounceFailed(ctx, s, attachResult, aErr)
		log.Printf("action: flowspec announce failed announcement_id=%d: %v",
			attachResult.AnnouncementID, aErr)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed", ErrorMessage: fmt.Sprintf("speaker: %v", aErr),
			RequestBody:    flowspec.Describe(rule),
			ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
		}, aErr
	}

	detail := fmt.Sprintf("flowspec rule %s announced (announcement_id=%d)", rule.Name, attachResult.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkAnnounced(ctx, attachResult.AnnouncementID, attachResult.Gen); mErr != nil {
		log.Printf("action: flowspec MarkAnnounced announcement_id=%d: %v", attachResult.AnnouncementID, mErr)
		detail += "; state write failed"
	}
	log.Printf("action: flowspec announce %s rule=%s connector=%s announcement_id=%d",
		rule.Prefix, rule.Name, conn.Name, attachResult.AnnouncementID)
	return &store.ActionExecutionLog{
		AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
		TriggerPhase: triggerPhase, ResponseName: responseName,
		ConnectorName: conn.Name, ConnectorID: &connID,
		Status: "success", Detail: detail,
		RequestBody:    flowspec.Describe(rule),
		ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
	}, nil
}

// markAnnounceFailed compensates a failed announce by marking the announcement
// failed. A stale-generation result is benign (a newer generation owns the
// row) and is not counted as a state-write failure.
func markAnnounceFailed(ctx context.Context, s store.Store, res store.BGPAttachResult, cause error) {
	err := retryBGPStateWrite(func(writeCtx context.Context) error {
		return s.BGPAnnouncements().MarkFailedAnnounce(writeCtx, res.AnnouncementID, res.Gen, cause.Error())
	})
	if err == nil || bgpStateNotApplied(err, res.AnnouncementID, res.Gen, "failed_announce") {
		return
	}
	metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
	log.Printf("ERROR action: compensate announce failure announcement_id=%d: %v", res.AnnouncementID, err)
}

// markWithdrawFailed compensates a failed withdraw by marking the announcement
// failed. A stale-generation result is benign and is not counted as a
// state-write failure.
func markWithdrawFailed(ctx context.Context, s store.Store, announcementID, gen int, cause string) {
	err := retryBGPStateWrite(func(writeCtx context.Context) error {
		return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, announcementID, gen, cause)
	})
	if err == nil || bgpStateNotApplied(err, announcementID, gen, "failed_withdraw") {
		return
	}
	metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
	log.Printf("ERROR action: bgp MarkFailedWithdraw announcement_id=%d: %v", announcementID, err)
}

func flowspecWithdraw(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	rule := flowspec.Rule{Name: flowspecRuleName(dstIP), Prefix: dstIP, Action: flowspec.ActionDrop}
	externalRuleID := fmt.Sprintf("%s|%s", rule.Prefix, rule.Name)
	connID := conn.ID
	actID := act.ID

	if overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); err != nil {
		log.Printf("action: flowspec withdraw override lookup: %v", err)
	} else if overridden {
		return recordSkip(&store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "skipped",
			SkipReason:     SkipReasonManualOverride,
			ErrorMessage:   "force-removed by operator",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, SkipReasonManualOverride), nil
	}

	result, err := s.BGPAnnouncements().Detach(ctx, attackDBID, rule.Prefix, rule.Name, connID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("detach: %v", err),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	if result.AnnouncementID == 0 {
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         "no flowspec announcement to detach (idempotent)",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	if !result.NeedWithdraw {
		detail := fmt.Sprintf("detached from flowspec announcement_id=%d (refcount=%d, kept active)",
			result.AnnouncementID, result.RefcountAfter)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         detail,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// The announced rule may carry match components (protocol, ports) that the
	// withdraw path cannot derive from the prefix alone. Rebuild the rule from
	// the announcement row so the speaker withdraws the same path it announced.
	// A lookup failure fails closed: withdrawing a dstIP-derived rule would
	// delete nothing (or the wrong path) while MarkWithdrawn hides the row.
	ann, gErr := s.BGPAnnouncements().Get(ctx, result.AnnouncementID)
	if gErr == nil && ann == nil {
		gErr = fmt.Errorf("announcement %d not found", result.AnnouncementID)
	}
	if gErr != nil {
		log.Printf("action: flowspec withdraw announcement lookup id=%d: %v", result.AnnouncementID, gErr)
		msg := fmt.Sprintf("announcement lookup: %v", gErr)
		markWithdrawFailed(ctx, s, result.AnnouncementID, result.Gen, msg)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed", ErrorMessage: msg,
			ExternalRuleID: externalRuleID, ExecutedAt: time.Now(),
		}, errors.New(msg)
	}
	rebuilt := flowspecRuleFromSpec(*ann)
	rule.Protocol = rebuilt.Protocol
	rule.DstPort = rebuilt.DstPort
	rule.SrcPort = rebuilt.SrcPort
	rule.Action = rebuilt.Action
	rule.RateLimit = rebuilt.RateLimit

	sp := bgp.Shared()
	if sp == nil {
		msg := "bgp speaker not configured: set up Settings → BGP Instance first"
		markWithdrawFailed(ctx, s, result.AnnouncementID, result.Gen, msg)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed", ErrorMessage: msg,
			ExternalRuleID: externalRuleID, ExecutedAt: time.Now(),
		}, errors.New(msg)
	}

	t0 := time.Now()
	wErr := sp.WithdrawFlowspec(ctx, rule)
	durationMs := int(time.Since(t0).Milliseconds())
	if wErr != nil {
		markWithdrawFailed(ctx, s, result.AnnouncementID, result.Gen, wErr.Error())
		log.Printf("action: flowspec withdraw failed announcement_id=%d: %v", result.AnnouncementID, wErr)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed", ErrorMessage: fmt.Sprintf("speaker: %v", wErr),
			RequestBody:    flowspec.Describe(rule),
			ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
		}, wErr
	}

	detail := fmt.Sprintf("flowspec rule %s withdrawn (announcement_id=%d)", rule.Name, result.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkWithdrawn(ctx, result.AnnouncementID, result.Gen); mErr != nil {
		log.Printf("action: flowspec MarkWithdrawn announcement_id=%d: %v", result.AnnouncementID, mErr)
		detail += "; state write failed"
	}
	log.Printf("action: flowspec withdraw %s rule=%s connector=%s announcement_id=%d",
		rule.Prefix, rule.Name, conn.Name, result.AnnouncementID)
	return &store.ActionExecutionLog{
		AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
		TriggerPhase: triggerPhase, ResponseName: responseName,
		ConnectorName: conn.Name, ConnectorID: &connID,
		Status: "success", Detail: detail,
		RequestBody:    flowspec.Describe(rule),
		ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
	}, nil
}
