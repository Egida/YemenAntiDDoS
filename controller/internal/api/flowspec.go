package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// jsonOrNil marshals a change payload for the audit publisher.
func jsonOrNil(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// flowspecView is the console read model for one Flowspec announcement.
type flowspecView struct {
	AnnouncementID int             `json:"announcement_id"`
	Prefix         string          `json:"prefix"`
	RuleName       string          `json:"rule_name"`
	ConnectorID    int             `json:"connector_id"`
	ConnectorName  string          `json:"connector_name"`
	Status         string          `json:"status"`
	Refcount       int             `json:"refcount"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	AnnouncedAt    time.Time       `json:"announced_at"`
	DelayStartedAt *time.Time      `json:"delay_started_at,omitempty"`
	DelayMinutes   int             `json:"delay_minutes"`
	Rule           *flowspec.Rule  `json:"rule,omitempty"`
	Match          string          `json:"match,omitempty"`
	Attacks        []flowspecActor `json:"attacks,omitempty"`
}

type flowspecActor struct {
	AttackID   int        `json:"attack_id"`
	ActionID   *int       `json:"action_id,omitempty"`
	DetachedAt *time.Time `json:"detached_at,omitempty"`
	AttachedAt time.Time  `json:"attached_at"`
}

func ruleFromAnnouncement(a store.BGPAnnouncement) flowspec.Rule {
	var rule flowspec.Rule
	if strings.TrimSpace(a.RuleSpec) != "" {
		if err := json.Unmarshal([]byte(a.RuleSpec), &rule); err != nil {
			rule = flowspec.Rule{}
		}
	}
	if rule.Name == "" {
		rule.Name = a.RouteMap
	}
	if rule.Prefix == "" {
		rule.Prefix = a.Prefix
	}
	if rule.Action == "" {
		rule.Action = flowspec.ActionDrop
	}
	return rule
}

func strictRuleFromAnnouncement(a store.BGPAnnouncement) (flowspec.Rule, error) {
	if strings.TrimSpace(a.RuleSpec) == "" {
		return flowspec.Rule{Name: a.RouteMap, Prefix: a.Prefix, Action: flowspec.ActionDrop}, nil
	}
	var rule flowspec.Rule
	if err := json.Unmarshal([]byte(a.RuleSpec), &rule); err != nil {
		return flowspec.Rule{}, fmt.Errorf("announcement %d rule_spec invalid: %w", a.ID, err)
	}
	return rule, nil
}

func buildFlowspecView(a store.BGPAnnouncement, conn *store.BGPConnector) flowspecView {
	name := ""
	if conn != nil {
		name = conn.Name
	}
	rule := ruleFromAnnouncement(a)
	return flowspecView{
		AnnouncementID: a.ID, Prefix: a.Prefix, RuleName: rule.Name,
		ConnectorID: a.ConnectorID, ConnectorName: name,
		Status: a.Status, Refcount: a.Refcount, ErrorMessage: a.ErrorMessage,
		AnnouncedAt: a.AnnouncedAt, DelayStartedAt: a.DelayStartedAt,
		DelayMinutes: a.DelayMinutes, Rule: &rule, Match: flowspec.Describe(rule),
	}
}

// listFlowspecAnnouncements returns every in-flight Flowspec rule with the
// attacks that keep it alive.
func listFlowspecAnnouncements(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		anns, err := deps.Store.BGPAnnouncements().ListActive(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		conns, err := deps.Store.BGPConnectors().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		byID := make(map[int]*store.BGPConnector, len(conns))
		for i := range conns {
			byID[conns[i].ID] = &conns[i]
		}

		views := make([]flowspecView, 0, len(anns))
		for _, a := range anns {
			if a.Kind != "flowspec" {
				continue
			}
			v := buildFlowspecView(a, byID[a.ConnectorID])
			if attacks, aErr := deps.Store.BGPAnnouncements().ListAttacks(c, a.ID); aErr == nil {
				for _, at := range attacks {
					v.Attacks = append(v.Attacks, flowspecActor{
						AttackID:   at.AttackID,
						ActionID:   at.ActionID,
						DetachedAt: at.DetachedAt,
						AttachedAt: at.AttachedAt,
					})
				}
			}
			views = append(views, v)
		}
		ok(c, gin.H{"announcements": views})
	}
}

// previewFlowspecRule validates and describes a rule without touching the speaker.
func previewFlowspecRule(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name     string  `json:"name"`
			Prefix   string  `json:"prefix" binding:"required"`
			Protocol *uint8  `json:"protocol"`
			DstPort  *uint16 `json:"dst_port"`
			SrcPort  *uint16 `json:"src_port"`
			Action   string  `json:"action"`
			Rate     uint64  `json:"rate_limit"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		rule := flowspec.Rule{
			Name:      strings.TrimSpace(req.Name),
			Prefix:    strings.TrimSpace(req.Prefix),
			Protocol:  req.Protocol,
			DstPort:   req.DstPort,
			SrcPort:   req.SrcPort,
			Action:    flowspec.Action(req.Action),
			RateLimit: req.Rate,
		}
		if rule.Name == "" {
			rule.Name = "preview-rule"
		}
		if err := rule.Validate(); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		ok(c, gin.H{"rule": rule, "match": flowspec.Describe(rule)})
	}
}

// forceWithdrawFlowspec removes a Flowspec rule from the speaker regardless of
// the announcement's refcount, mirroring the RTBH orphan force-withdraw path.
func forceWithdrawFlowspec(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid announcement id")
			return
		}
		if deps.ActionEngine != nil {
			unlock := deps.ActionEngine.LockAnnouncement(id)
			defer unlock()
		}

		ann, err := deps.Store.BGPAnnouncements().Get(c, id)
		if err != nil || ann == nil {
			errResponse(c, http.StatusNotFound, "announcement not found")
			return
		}
		if ann.Kind != "flowspec" {
			errResponse(c, http.StatusBadRequest,
				fmt.Sprintf("announcement %d is kind=%s; use the RTBH force-remove endpoint", ann.ID, ann.Kind))
			return
		}
		if ann.Status == "withdrawn" {
			ok(c, gin.H{"ok": true, "announcement_id": ann.ID, "already_withdrawn": true})
			return
		}

		rule, ruleErr := strictRuleFromAnnouncement(*ann)
		if ruleErr != nil {
			log.Printf("api: flowspec force withdraw announcement_id=%d: %v", ann.ID, ruleErr)
			errResponse(c, http.StatusConflict, "flowspec announcement has malformed rule_spec; refusing withdrawal")
			return
		}
		if ruleErr = rule.Validate(); ruleErr != nil {
			log.Printf("api: flowspec force withdraw announcement_id=%d: invalid rule: %v", ann.ID, ruleErr)
			errResponse(c, http.StatusConflict, "flowspec announcement has an invalid rule; refusing withdrawal")
			return
		}
		_, gen, err := deps.Store.BGPAnnouncements().ForceWithdraw(c, ann.ID)
		if err != nil {
			dbError(c, "", err)
			return
		}
		if deps.ActionEngine != nil {
			if gen != ann.Gen {
				deps.ActionEngine.NoteAnnouncementTakeover(ann.ID)
			}
			deps.ActionEngine.CancelAnnouncementDelay(ann.ID, gen, "flowspec force withdraw")
		}
		sp := bgp.Shared()
		if sp != nil {
			if wErr := sp.WithdrawFlowspec(c, rule); wErr != nil {
				if mErr := deps.Store.BGPAnnouncements().MarkFailedWithdraw(c, ann.ID, gen, wErr.Error()); mErr != nil {
					dbError(c, "", mErr)
					return
				}
				log.Printf("api: flowspec force withdraw announcement_id=%d speaker failed: %v", ann.ID, wErr)
				ok(c, gin.H{"ok": true, "announcement_id": ann.ID, "warning": fmt.Sprintf("speaker error: %v (row marked failed)", wErr)})
				return
			}
		} else {
			log.Printf("api: flowspec force withdraw announcement_id=%d: speaker not configured; DB row withdrawn only", ann.ID)
		}
		if mErr := deps.Store.BGPAnnouncements().MarkWithdrawn(c, ann.ID, gen); mErr != nil {
			dbError(c, "", mErr)
			return
		}
		publishAfterChange(c, deps, "flowspec_force_withdraw", fmt.Sprintf("%d", ann.ID), "force_withdraw",
			jsonOrNil(map[string]any{"announcement_id": ann.ID, "rule": rule.Name}))
		log.Printf("api: flowspec force withdraw announcement_id=%d rule=%s", ann.ID, rule.Name)
		ok(c, gin.H{"ok": true, "announcement_id": ann.ID})
	}
}
