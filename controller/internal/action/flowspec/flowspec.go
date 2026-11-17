// Package flowspec defines the vendor-neutral Flowspec rule model consumed by
// the embedded GoBGP speaker. It contains no I/O, subprocess execution, or
// vendor-specific rendering.
package flowspec

import (
	"fmt"
	"strconv"
	"strings"
)

// Action is the terminal treatment for matched traffic.
type Action string

const (
	ActionDrop      Action = "drop"
	ActionRateLimit Action = "rate-limit"
)

// Rule is the vendor-neutral description of one Flowspec entry.
//
// Only the fields that are set are matched; an unset port or protocol yields a
// broader match, so callers should set every field they can defend.
type Rule struct {
	// Name is the stable identifier used for withdraw and for logs. Required.
	Name string
	// Prefix is the destination prefix, e.g. 198.51.100.7/32. Required.
	Prefix string
	// SrcPrefix is the optional source prefix match component (RFC 8955 type 2).
	SrcPrefix string
	// Protocol is the IP protocol number (6=TCP, 17=UDP); nil omits the match.
	Protocol *uint8
	// DstPort / SrcPort are TCP/UDP ports; nil omits the match.
	DstPort *uint16
	SrcPort *uint16
	// Action is drop or rate-limit. Empty defaults to drop.
	Action Action
	// RateLimit is bytes per second; required when Action is rate-limit.
	RateLimit uint64
}

// Validate reports whether the rule is complete and internally consistent.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("flowspec: rule name is required")
	}
	if strings.TrimSpace(r.Prefix) == "" {
		return fmt.Errorf("flowspec: destination prefix is required")
	}
	act := r.Action
	if act == "" {
		act = ActionDrop
	}
	if act != ActionDrop && act != ActionRateLimit {
		return fmt.Errorf("flowspec: unsupported action %q", r.Action)
	}
	if act == ActionRateLimit && r.RateLimit == 0 {
		return fmt.Errorf("flowspec: rate-limit action requires a positive rate")
	}
	return nil
}

func (r Rule) action() Action {
	if r.Action == "" {
		return ActionDrop
	}
	return r.Action
}

// Describe renders a human-readable match tuple for logs and the console.
func Describe(r Rule) string {
	parts := []string{"destination " + r.Prefix}
	if r.SrcPrefix != "" {
		parts = append(parts, "source "+r.SrcPrefix)
	}
	if r.Protocol != nil {
		parts = append(parts, "protocol "+protoName(*r.Protocol))
	}
	if r.DstPort != nil {
		parts = append(parts, fmt.Sprintf("destination-port %d", *r.DstPort))
	}
	if r.SrcPort != nil {
		parts = append(parts, fmt.Sprintf("source-port %d", *r.SrcPort))
	}
	if r.action() == ActionRateLimit {
		parts = append(parts, fmt.Sprintf("rate-limit %d B/s (traffic-rate %.0f)", r.RateLimit, float64(r.RateLimit)))
	} else {
		parts = append(parts, "drop (traffic-rate 0)")
	}
	return strings.Join(parts, ", ")
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	default:
		return strconv.Itoa(int(p))
	}
}
