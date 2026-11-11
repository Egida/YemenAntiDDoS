package bgp

import (
	"fmt"
	"net"
	"strings"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

// blackholeCommunity is the RFC 7999 well-known BLACKHOLE community 65535:666.
const blackholeCommunity = 0xFFFF0000 | 666

func parsePrefix(s string) (net.IP, *net.IPNet, error) {
	s = strings.TrimSpace(s)
	if ip, ipNet, err := net.ParseCIDR(s); err == nil {
		return ip, ipNet, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	return nil, nil, fmt.Errorf("bgp: invalid prefix %q", s)
}

func numericItem(value uint64) *bgp.FlowSpecComponentItem {
	return bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, value)
}

// encodeFlowspec converts a vendor-neutral rule into a GoBGP NLRI plus path
// attributes. Flowspec NLRI carries no next-hop (RFC 8955 §4); the terminal
// action rides the traffic-rate-bytes ext-community (drop = rate 0).
// Components are appended in RFC type order: dst-prefix(1), proto(3),
// dst-port(5), src-port(6).
func encodeFlowspec(rule flowspec.Rule) (key string, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface, err error) {
	if err := rule.Validate(); err != nil {
		return "", nil, nil, err
	}
	ip, ipNet, err := parsePrefix(rule.Prefix)
	if err != nil {
		return "", nil, nil, err
	}
	ones, _ := ipNet.Mask.Size()
	base := ipNet.IP.String() // host bits masked off

	var rules []bgp.FlowSpecComponentInterface
	family := "fs4"
	if ip.To4() != nil {
		rules = append(rules, bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(uint8(ones), base)))
	} else {
		family = "fs6"
		rules = append(rules, bgp.NewFlowSpecDestinationPrefix6(bgp.NewIPv6AddrPrefix(uint8(ones), base), 0))
	}
	if rule.Protocol != nil {
		rules = append(rules, bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO,
			[]*bgp.FlowSpecComponentItem{numericItem(uint64(*rule.Protocol))}))
	}
	if rule.DstPort != nil {
		rules = append(rules, bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT,
			[]*bgp.FlowSpecComponentItem{numericItem(uint64(*rule.DstPort))}))
	}
	if rule.SrcPort != nil {
		rules = append(rules, bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_SRC_PORT,
			[]*bgp.FlowSpecComponentItem{numericItem(uint64(*rule.SrcPort))}))
	}

	// flowspec.Rule.action() is unexported; inline the empty→drop default here.
	act := rule.Action
	if act == "" {
		act = flowspec.ActionDrop
	}
	rate := float32(0) // traffic-rate 0 = discard (RFC 8955 §7.1)
	if act == flowspec.ActionRateLimit {
		rate = float32(rule.RateLimit) // Rule.RateLimit is bytes/sec, RFC 8955's unit
	}
	attrs = []bgp.PathAttributeInterface{
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTrafficRateExtended(0, rate),
		}),
	}
	if family == "fs4" {
		nlri = bgp.NewFlowSpecIPv4Unicast(rules)
	} else {
		nlri = bgp.NewFlowSpecIPv6Unicast(rules)
	}
	key = fmt.Sprintf("%s|%s|%s|%s|%s", family, ipNet.String(), protoKey(rule), portKey(rule.DstPort), portKey(rule.SrcPort))
	return key, nlri, attrs, nil
}

func protoKey(r flowspec.Rule) string {
	if r.Protocol == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *r.Protocol)
}

func portKey(p *uint16) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *p)
}

// encodeBlackhole builds the RTBH origination: unicast prefix with next-hop
// self (or the configured rtbh_next_hop) + RFC 7999 BLACKHOLE community.
func encodeBlackhole(prefix, nextHop string) (key string, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface, err error) {
	ip, ipNet, err := parsePrefix(prefix)
	if err != nil {
		return "", nil, nil, err
	}
	if net.ParseIP(nextHop) == nil {
		return "", nil, nil, fmt.Errorf("bgp: invalid rtbh next-hop %q", nextHop)
	}
	ones, _ := ipNet.Mask.Size()
	communities := bgp.NewPathAttributeCommunities([]uint32{blackholeCommunity})
	if ip.To4() != nil {
		nlri = bgp.NewIPAddrPrefix(uint8(ones), ipNet.IP.String())
		attrs = []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			bgp.NewPathAttributeNextHop(nextHop),
			communities,
		}
		key = fmt.Sprintf("rtbh4|%s", ipNet.String())
		return key, nlri, attrs, nil
	}
	nlri = bgp.NewIPv6AddrPrefix(uint8(ones), ipNet.IP.String())
	attrs = []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{nlri}),
		communities,
	}
	key = fmt.Sprintf("rtbh6|%s", ipNet.String())
	return key, nlri, attrs, nil
}
