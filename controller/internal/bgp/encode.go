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
	var ip net.IP
	var ipNet *net.IPNet
	if a, n, err := net.ParseCIDR(s); err == nil {
		ip, ipNet = a, n
	} else if p := net.ParseIP(s); p != nil {
		if p.To4() != nil {
			ipNet = &net.IPNet{IP: p, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: p, Mask: net.CIDRMask(128, 128)}
		}
		ip = p
	} else {
		return nil, nil, fmt.Errorf("bgp: invalid prefix %q", s)
	}
	// An IPv4-mapped IPv6 input (::ffff:a.b.c.d[/len]) must become plain IPv4;
	// a mapped /128 would otherwise encode as an IPv4 prefix of length 128.
	if ip.To4() != nil {
		ones, _ := ipNet.Mask.Size()
		if ones > 32 {
			return nil, nil, fmt.Errorf("bgp: prefix %q: length %d exceeds IPv4 maximum of 32", s, ones)
		}
		ip = ip.To4()
		ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)}
	}
	return ip, ipNet, nil
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
		// RFC 8955 §7.1 encodes traffic-rate as IEEE-754 single precision, so
		// float32 here loses nothing that survives the wire format.
		rate = float32(rule.RateLimit) // Rule.RateLimit is bytes/sec, RFC 8955's unit
	}
	communities := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
		bgp.NewTrafficRateExtended(0, rate),
	})
	// RFC 8955 §4: flowspec receivers ignore next-hop, but gobgp's API layer
	// still requires one (api2Path) plus Origin (fixupApiPath) on non-withdraw
	// paths. NEXT_HOP is the only carrier that survives the API marshal round
	// trip for flowspec SAFIs (MpReach next-hops are stripped there, and an
	// empty-NLRI MpReach is rejected); api2Path consumes the NEXT_HOP attr and
	// re-marshals the NLRI as MP_REACH with zero-length next-hop internally.
	nh := "0.0.0.0"
	if family == "fs6" {
		nh = "::"
	}
	attrs = append(attrs,
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeNextHop(nh),
		communities,
	)
	if family == "fs4" {
		nlri = bgp.NewFlowSpecIPv4Unicast(rules)
	} else {
		nlri = bgp.NewFlowSpecIPv6Unicast(rules)
	}
	// The key deliberately excludes Action/RateLimit: one logical rule per
	// match tuple, so a rate change updates the existing path's attributes
	// instead of orphaning the previously announced one.
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
	// MP_REACH must carry an IPv6 next-hop for a v6 route. The default
	// rtbh_next_hop/router-id is IPv4, so fall back to the unspecified
	// address and let gobgp rewrite it per-peer (next-hop self).
	nh := "::"
	if n6 := net.ParseIP(nextHop).To16(); n6 != nil && n6.To4() == nil {
		nh = nextHop
	}
	attrs = []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeMpReachNLRI(nh, []bgp.AddrPrefixInterface{nlri}),
		communities,
	}
	key = fmt.Sprintf("rtbh6|%s", ipNet.String())
	return key, nlri, attrs, nil
}
