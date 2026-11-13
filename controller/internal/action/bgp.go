package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// isIPv6 determines whether a prefix or IP string is IPv6.
// Handles both CIDR ("2001:db8::/32") and plain IP ("2001:db8::1") forms.
func isIPv6(s string) bool {
	if _, cidr, err := net.ParseCIDR(s); err == nil {
		return cidr.IP.To4() == nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	return false
}

// splitExternalRuleID splits "{prefix}|{route_map}" into (prefix, routeMap).
// Uses "|" as separator to avoid collision with ":" in IPv6 addresses.
// Falls back to ":" for backward compatibility with pre-v1.1.1 records.
func splitExternalRuleID(ruleID string) []string {
	if idx := strings.LastIndex(ruleID, "|"); idx >= 0 {
		return []string{ruleID[:idx], ruleID[idx+1:]}
	}
	// Backward compat: old records used ":" separator.
	// Use LastIndex to handle IPv6 addresses like "2001:db8::1/128:RTBH".
	if idx := strings.LastIndex(ruleID, ":"); idx >= 0 {
		return []string{ruleID[:idx], ruleID[idx+1:]}
	}
	return []string{ruleID}
}

// executeBGP injects or withdraws a BGP route through the embedded speaker.
// on_detected: Attach to announcement; announce if refcount→1
// on_expired:  Detach from announcement; withdraw if refcount→0 and delay=0
//
// The `engine` parameter is required for the delayed-withdraw path (PR-5
// arms timers via engine.ScheduleDelay with announcement_id). Can be nil
// when called from recovery/tests that drive timers externally.
func executeBGP(ctx context.Context, s store.Store, engine *Engine, act store.ResponseAction,
	attack *store.Attack, eventType, prefixStr, responseName, triggerPhase string,
	attackDBID int, fa func() *FlowAnalysis) (*store.ActionExecutionLog, error) {

	conn, err := s.BGPConnectors().Get(ctx, *act.BGPConnectorID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "failed",
			ConnectorID:  act.BGPConnectorID,
			ErrorMessage: fmt.Sprintf("bgp connector %d not found: %v", *act.BGPConnectorID, err),
			ExecutedAt:   time.Now(),
		}, err
	}

	if !conn.Enabled {
		return recordSkip(&store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      act.ID,
			ActionType:    "bgp",
			TriggerPhase:  triggerPhase,
			ResponseName:  responseName,
			ConnectorName: conn.Name,
			Status:        "skipped",
			ErrorMessage:  "bgp connector disabled",
			ExecutedAt:    time.Now(),
		}, SkipReasonConnectorDisabled), nil
	}

	// Determine the target prefix/IP to announce or withdraw
	dstIP := attack.DstIP
	// Ensure mask suffix for plain IPs (internal_ip domain): /32 for IPv4, /128 for IPv6
	if !strings.Contains(dstIP, "/") {
		if isIPv6(dstIP) {
			dstIP = dstIP + "/128"
		} else {
			dstIP = dstIP + "/32"
		}
	}

	// Speaker guard comes before the flowspec/RTBH split so both kinds fail
	// closed identically (skip, no announcement row) when no BGP Instance is
	// configured.
	sp := bgp.Shared()
	if sp == nil {
		return recordSkip(&store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      act.ID,
			ActionType:    "bgp",
			TriggerPhase:  triggerPhase,
			ResponseName:  responseName,
			ConnectorName: conn.Name,
			ConnectorID:   act.BGPConnectorID,
			Status:        "skipped",
			ErrorMessage:  "bgp speaker not configured: set up Settings → BGP Instance first",
			ExecutedAt:    time.Now(),
		}, SkipReasonSpeakerNotConfigured), nil
	}

	if conn.FlowspecEnabled {
		return executeBGPFlowspec(ctx, s, conn, act, attack, dstIP, attackDBID, responseName, triggerPhase)
	}

	switch triggerPhase {
	case "on_detected":
		return bgpAnnounce(ctx, s, engine, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	case "on_expired":
		return bgpWithdraw(ctx, s, engine, conn, act, dstIP, attackDBID, responseName, triggerPhase)
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

// bgpAnnounce attaches this attack to an announcement (creating one if
// necessary) and announces the route only when the refcount-based manager
// tells us this is a new announcement.
//
// v1.2 PR-5: multiple attacks sharing the same (prefix, route_map, connector)
// attach to a single announcement. Only the first attack triggers the speaker,
// while subsequent attaches just bump the refcount.
//
// `engine` is used to cancel any in-memory delay timer if this attach
// resurrected a delayed announcement. Can be nil in tests / recovery paths
// that don't care about the timer.
func bgpAnnounce(ctx context.Context, s store.Store, engine *Engine, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	actID := act.ID
	connID := conn.ID

	if overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); err != nil {
		log.Printf("action: bgp announce override lookup: %v", err)
	} else if overridden {
		logCtx, cancel := execLogContext()
		writeSkipLog(logCtx, s, attackDBID, act, responseName, conn.Name, SkipReasonManualOverride, "")
		cancel()
		return nil, nil
	}

	// Look up the attack's per-action bgp_withdraw_delay — this attack's
	// contribution to the announcement's effective delay. The announcement's
	// final delay is MAX across all attached attacks.
	delayMinutes := act.BGPWithdrawDelayMinutes

	attachResult, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID:     attackDBID,
		ActionID:     &actID,
		ResponseName: responseName,
		DelayMinutes: delayMinutes,
		Prefix:       dstIP,
		RouteMap:     routeMap,
		ConnectorID:  connID,
	})
	if err != nil {
		log.Printf("action: bgp attach failed attack=%d prefix=%s: %v", attackDBID, dstIP, err)
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
		// Shared attach (refcount++ on existing active announcement) OR
		// delay-cancelling attach (refcount 0→1 resurrecting a delayed
		// announcement). In either case, no speaker call is needed. If the announcement
		// was in delayed state, the Attach already transitioned status back
		// to active in DB — but we ALSO need to cancel the in-memory timer
		// goroutine so it doesn't fire withdrawal. Idempotent: if no timer is
		// armed the map lookup is a miss and CancelAnnouncementDelay no-ops.
		if engine != nil {
			engine.CancelAnnouncementDelay(attachResult.AnnouncementID, attachResult.Gen, "rebreach: attack attached during delay")
		}
		log.Printf("action: bgp attach shared prefix=%s announcement_id=%d attack=%d",
			dstIP, attachResult.AnnouncementID, attackDBID)
		detail := fmt.Sprintf("attached to announcement_id=%d (shared)", attachResult.AnnouncementID)
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
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   msg,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, errors.New(msg)
	}

	// First attach — originate the blackhole route.
	t0 := time.Now()
	aErr := sp.AnnounceBlackhole(ctx, dstIP)
	durationMs := int(time.Since(t0).Milliseconds())

	if aErr != nil {
		log.Printf("action: bgp announce failed announcement_id=%d: %v", attachResult.AnnouncementID, aErr)
		detail := ""
		errorMessage := fmt.Sprintf("speaker: %v", aErr)
		cErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return s.BGPAnnouncements().MarkFailedAnnounce(writeCtx, attachResult.AnnouncementID, attachResult.Gen, aErr.Error())
		})
		if bgpStateNotApplied(cErr, attachResult.AnnouncementID, attachResult.Gen, "failed_announce") {
			detail = bgpNotAppliedDetail
		} else if cErr != nil {
			metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
			log.Printf("ERROR action: bgp compensate announce failure announcement_id=%d: %v",
				attachResult.AnnouncementID, cErr)
		}
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   errorMessage,
			Detail:         detail,
			RequestBody:    "blackhole " + dstIP,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, aErr
	}

	detail := fmt.Sprintf("triggered announcement_id=%d", attachResult.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkAnnounced(ctx, attachResult.AnnouncementID, attachResult.Gen); bgpStateNotApplied(mErr, attachResult.AnnouncementID, attachResult.Gen, "announced") {
		detail += "; " + bgpNotAppliedDetail
	} else if mErr != nil {
		log.Printf("action: bgp MarkAnnounced announcement_id=%d: %v", attachResult.AnnouncementID, mErr)
	}
	log.Printf("action: bgp announce %s connector=%s announcement_id=%d",
		dstIP, conn.Name, attachResult.AnnouncementID)
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
		RequestBody:    "blackhole " + dstIP,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// bgpWithdraw detaches this attack from the announcement. Depending on
// refcount/delay the manager tells us whether to withdraw immediately,
// arm a delay timer, or do nothing (shared detach).
//
// v1.2 PR-5: when multiple attacks share an announcement, only the LAST
// detach triggers the speaker withdrawal.
//
// `engine` must be non-nil when the delayed-withdraw path can trigger (i.e.
// when any attached attack carries a non-zero bgp_withdraw_delay). Recovery
// paths that already hold the timer state can pass nil.
func bgpWithdraw(ctx context.Context, s store.Store, engine *Engine, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	connID := conn.ID
	actID := act.ID

	// Per-artifact manual_override: if operator already force-removed this
	// attack's artifact, emit a skip log and return. Detach is idempotent
	// anyway, but an explicit skip log keeps the audit trail clean.
	overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID)
	if err != nil {
		log.Printf("action: bgp withdraw override lookup: %v", err)
	}
	if overridden {
		log.Printf("action: bgp withdraw skipping %s (manual override, attack=%d)", externalRuleID, attackDBID)
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

	result, err := s.BGPAnnouncements().Detach(ctx, attackDBID, dstIP, routeMap, connID)
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
		// No announcement found — attack never attached. Idempotent success.
		log.Printf("action: bgp detach no-op (no announcement) attack=%d prefix=%s", attackDBID, dstIP)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         "no announcement to detach (idempotent)",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Shared detach: refcount > 0 after decrement, nothing to do.
	if !result.NeedWithdraw && !result.Delayed {
		log.Printf("action: bgp detach shared announcement_id=%d refcount=%d attack=%d",
			result.AnnouncementID, result.RefcountAfter, attackDBID)
		detail := fmt.Sprintf("detached from announcement_id=%d (refcount=%d, kept active)",
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

	// Delayed path: the announcement is already in 'delayed' status.
	// Arm a persistent delay timer keyed on announcement_id. When the timer
	// fires (or is cancelled by re-breach), perform or skip the withdraw.
	if result.Delayed {
		delay := time.Duration(result.DelayMinutes) * time.Minute
		scheduledFor := time.Now().Add(delay)
		annID := result.AnnouncementID

		if engine == nil {
			// No engine reference — recovery path manages its own timer.
			// Just return the scheduled log.
			detail := fmt.Sprintf("delayed withdraw in %dm (announcement_id=%d, timer externally managed)",
				result.DelayMinutes, annID)
			return &store.ActionExecutionLog{
				AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
				TriggerPhase: triggerPhase, ResponseName: responseName,
				ConnectorName: conn.Name, ConnectorID: &connID,
				Status:         "scheduled",
				Detail:         detail,
				ScheduledFor:   &scheduledFor,
				ExternalRuleID: externalRuleID,
				ExecutedAt:     time.Now(),
			}, nil
		}

		schedID, cancelCtx, perr := engine.ScheduleDelayForAnnouncement(ctx, annID, result.Gen, scheduledFor)
		if bgpStateNotApplied(perr, annID, result.Gen, "schedule") {
			return recordSkip(&store.ActionExecutionLog{AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp", TriggerPhase: triggerPhase,
				ResponseName: responseName, ConnectorName: conn.Name, ConnectorID: &connID, ExternalRuleID: externalRuleID,
				Status: "skipped", Detail: "superseded by newer announcement generation", ExecutedAt: time.Now()}, SkipReasonStaleGeneration), nil
		}
		if perr != nil {
			log.Printf("action: bgp ScheduleDelay persist failed announcement_id=%d: %v", annID, perr)
			// Compensate: mark announcement failed so it doesn't linger in delayed forever.
			detail := ""
			if err := retryBGPStateWrite(func(writeCtx context.Context) error {
				return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, annID, result.Gen, fmt.Sprintf("schedule persist failed: %v", perr))
			}); bgpStateNotApplied(err, annID, result.Gen, "failed_withdraw") {
				detail = bgpNotAppliedDetail
			} else if err != nil {
				metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
				log.Printf("ERROR action: bgp MarkFailedWithdraw announcement_id=%d: %v", annID, err)
			}
			return &store.ActionExecutionLog{
				AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
				TriggerPhase: triggerPhase, ResponseName: responseName,
				ConnectorName: conn.Name, ConnectorID: &connID,
				Status:         "failed",
				ErrorMessage:   fmt.Sprintf("schedule persist failed: %v", perr),
				Detail:         detail,
				ExternalRuleID: externalRuleID,
				ExecutedAt:     time.Now(),
			}, perr
		}

		// Goroutine waits for timer or cancellation.
		go bgpDelayedWithdrawWorker(s, engine, conn, act, dstIP, routeMap, attackDBID,
			annID, schedID, result.Gen, cancelCtx, delay, responseName)

		detail := fmt.Sprintf("delayed withdraw in %dm (announcement_id=%d, scheduled_id=%d)",
			result.DelayMinutes, annID, schedID)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status:         "scheduled",
			Detail:         detail,
			ErrorMessage:   fmt.Sprintf("delayed withdraw in %dm", result.DelayMinutes),
			ScheduledFor:   &scheduledFor,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Immediate withdraw: refcount=0, delay=0. Detach already transitioned
	// the announcement to 'withdrawing'. Withdraw now and finalize.
	return performBGPWithdraw(ctx, s, conn, act, dstIP, routeMap, attackDBID, result.AnnouncementID, result.Gen, responseName, triggerPhase)
}

// bgpDelayedWithdrawWorker is the goroutine body that waits for the delay
// timer, then executes the actual BGP withdraw — or bails cleanly if the
// announcement was cancelled (re-breach, force-remove, or explicit cancel).
//
// v1.2 PR-5: all lifecycle bookkeeping (MarkExecuting, MarkWithdrawing,
// MarkWithdrawn, MarkFailedWithdraw, CompleteDelay, FailDelay) flows through
// the Engine so recovery can pick up from any interruption.
func bgpDelayedWithdrawWorker(s store.Store, engine *Engine, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, attackDBID, announcementID, schedID int, gen int,
	cancelCtx context.Context, delay time.Duration, responseName string) {

	log.Printf("action: bgp delayed withdraw scheduled in %v announcement_id=%d scheduled_id=%d",
		delay, announcementID, schedID)

	select {
	case <-time.After(delay):
		// Race guard — only one goroutine may execute this task.
		execCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !engine.MarkExecutingDelay(execCtx, schedID) {
			log.Printf("action: bgp delayed withdraw skipped scheduled_id=%d (no longer pending)", schedID)
			return
		}

		// Claim this generation's delayed announcement before the speaker withdrawal.
		// Returns false if concurrent attach cancelled (refcount now > 0).
		ok, mErr := s.BGPAnnouncements().MarkWithdrawing(execCtx, announcementID, gen)
		if mErr != nil {
			log.Printf("action: bgp delayed MarkWithdrawing announcement_id=%d: %v", announcementID, mErr)
			engine.FailDelayForAnnouncement(execCtx, schedID, announcementID, mErr.Error())
			return
		}
		if !ok {
			// Announcement is no longer in active/delayed — likely re-breached
			// and back to active with refcount > 0. Don't withdraw.
			log.Printf("action: bgp delayed withdraw bailing announcement_id=%d (no longer in delayed/active — likely re-breached)", announcementID)
			engine.CompleteDelayForAnnouncement(execCtx, schedID, announcementID)
			return
		}

		// Run the actual speaker withdrawal and finalize.
		execLog, wErr := performBGPWithdraw(execCtx, s, conn, act, dstIP, routeMap, attackDBID, announcementID, gen, responseName, "on_expired")
		if wErr != nil {
			engine.FailDelayForAnnouncement(execCtx, schedID, announcementID, wErr.Error())
		} else {
			engine.CompleteDelayForAnnouncement(execCtx, schedID, announcementID)
		}
		if execLog != nil {
			if _, err := writeExecLog(s, execLog); err != nil {
				log.Printf("action: create delayed bgp withdraw log: %v", err)
			}
		}

	case <-cancelCtx.Done():
		log.Printf("action: bgp delayed withdraw cancelled announcement_id=%d scheduled_id=%d", announcementID, schedID)
		// Cancel context was triggered by CancelAnnouncementDelay (re-breach)
		// or by ScheduleDelayForAnnouncement (reschedule). The caller already
		// manages the pendingDelay map entry — do NOT delete here, because a
		// reschedule may have already stored a new cancel func under the same
		// key, and deleting it would orphan the replacement timer.
	}
}

// PerformBGPWithdrawForOrphan is the exported wrapper over performBGPWithdraw
// used by the API layer's orphanForceWithdraw handler. Writes a
// manual_override audit log (not a normal on_expired) since there's no
// attack attached.
func PerformBGPWithdrawForOrphan(ctx context.Context, s store.Store, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, announcementID int, gen int) (*store.ActionExecutionLog, error) {
	return performBGPWithdraw(ctx, s, conn, act, dstIP, routeMap,
		0 /* no attack */, announcementID, gen, "" /* no response name */, "manual_override")
}

const bgpNotAppliedDetail = "state write not applied (newer generation or already final)"

func bgpStateNotApplied(err error, id, gen int, op string) bool {
	if !errors.Is(err, store.ErrStaleAnnouncement) {
		return false
	}
	log.Printf("INFO bgp state write not applied announcement_id=%d gen=%d op=%s", id, gen, op)
	metrics.BGPStaleWrites.WithLabelValues(op).Inc()
	return true
}

func retryBGPStateWrite(write func(context.Context) error) (err error) {
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		err = write(ctx)
		cancel()
		if err == nil || errors.Is(err, store.ErrStaleAnnouncement) {
			return err
		}
	}
	return err
}

// performBGPWithdraw runs the speaker withdrawal for a withdrawing-state
// announcement and transitions to withdrawn/failed.
// Called from bgpWithdraw's immediate branch and from the delayed goroutine.
func performBGPWithdraw(ctx context.Context, s store.Store, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, attackDBID, announcementID int, gen int,
	responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	stateError := ""
	stateDetail := fmt.Sprintf("announcement_id=%d", announcementID)
	recordStateError := func(err error, op string) {
		if bgpStateNotApplied(err, announcementID, gen, op) {
			stateDetail += "; " + bgpNotAppliedDetail
			return
		}
		metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
		log.Printf("ERROR action: bgp state write announcement_id=%d: %v", announcementID, err)
		stateError = fmt.Sprintf("; state write failed: %v", err)
	}
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	connID := conn.ID

	t0 := time.Now()
	sp := bgp.Shared()
	requestBody := "blackhole " + dstIP
	var wErr error
	if sp == nil {
		wErr = errors.New("bgp speaker not configured")
	} else if ann, gErr := s.BGPAnnouncements().Get(ctx, announcementID); gErr != nil {
		// Fail closed: guessing the kind could delete the wrong path.
		wErr = fmt.Errorf("announcement lookup: %w", gErr)
	} else if ann == nil {
		wErr = fmt.Errorf("announcement %d not found", announcementID)
	} else if ann.Kind == "flowspec" {
		// Flowspec announcements withdraw the stored rule — its match
		// components cannot be derived from the prefix alone.
		rule, rErr := flowspecRuleFromSpec(*ann)
		if rErr != nil {
			// Fail closed: the fallback rule is broader than the announced
			// path, and its key differs, so withdrawing it would leave the
			// original path installed.
			wErr = rErr
		} else {
			requestBody = flowspec.Describe(rule)
			wErr = sp.WithdrawFlowspec(ctx, rule)
		}
	} else {
		wErr = sp.WithdrawBlackhole(ctx, dstIP)
	}
	durationMs := int(time.Since(t0).Milliseconds())

	if wErr != nil {
		if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, announcementID, gen, wErr.Error())
		}); mErr != nil {
			recordStateError(mErr, "failed_withdraw")
		}
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("speaker: %v", wErr) + stateError,
			Detail:         stateDetail,
			RequestBody:    requestBody,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, wErr
	}

	log.Printf("action: bgp withdraw %s connector=%s announcement_id=%d", dstIP, conn.Name, announcementID)
	if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
		return s.BGPAnnouncements().MarkWithdrawn(writeCtx, announcementID, gen)
	}); mErr != nil {
		recordStateError(mErr, "withdrawn")
	}
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    &connID,
		Status:         "success",
		ErrorMessage:   strings.TrimPrefix(stateError, "; "),
		Detail:         stateDetail,
		RequestBody:    requestBody,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// RecoverBGPRoutes re-originates active/delayed announcements in the embedded
// speaker after a controller restart. Synchronous; runs before startup
// reconciliation. Flowspec rules rebuild from the stored rule_spec JSON;
// RTBH from the announcement prefix.
func RecoverBGPRoutes(ctx context.Context, s store.Store) {
	announcements, err := s.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		log.Printf("bgp recovery: list announcements: %v", err)
		return
	}
	sp := bgp.Shared()
	if sp == nil {
		log.Printf("bgp recovery: speaker not configured, skipping %d announcements", len(announcements))
		return
	}
	for _, ann := range announcements {
		if ann.Status != "active" && ann.Status != "delayed" {
			continue
		}
		if ann.Kind == "flowspec" {
			rule, rErr := flowspecRuleFromSpec(ann)
			if rErr != nil {
				// Skip the row: a broadened fallback rule would not match the
				// announced path.
				log.Printf("bgp recovery: flowspec announcement_id=%d: %v", ann.ID, rErr)
				continue
			}
			if err := sp.AnnounceFlowspec(ctx, rule); err != nil {
				log.Printf("bgp recovery: flowspec announcement_id=%d: %v", ann.ID, err)
			}
			continue
		}
		if err := sp.AnnounceBlackhole(ctx, ann.Prefix); err != nil {
			log.Printf("bgp recovery: rtbh announcement_id=%d %s: %v", ann.ID, ann.Prefix, err)
		}
	}
}

// flowspecRuleFromSpec rebuilds the rule from a flowspec announcement row.
// An empty rule_spec yields the row's identity fields (the legitimate empty
// case). A malformed rule_spec is an error: announcing or withdrawing the
// destination-only fallback would install a broader path than the one that
// was announced, and its encode key differs from the announced path's key.
func flowspecRuleFromSpec(ann store.BGPAnnouncement) (flowspec.Rule, error) {
	var rule flowspec.Rule
	if strings.TrimSpace(ann.RuleSpec) != "" {
		if err := json.Unmarshal([]byte(ann.RuleSpec), &rule); err != nil {
			log.Printf("WARN bgp: announcement %d rule_spec unmarshal failed: %v", ann.ID, err)
			return flowspec.Rule{}, fmt.Errorf("announcement %d rule_spec invalid: %w", ann.ID, err)
		}
	}
	if rule.Name == "" {
		rule.Name = ann.RouteMap
	}
	if rule.Prefix == "" {
		rule.Prefix = ann.Prefix
	}
	if rule.Action == "" {
		rule.Action = flowspec.ActionDrop
	}
	return rule, nil
}
