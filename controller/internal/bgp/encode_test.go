package bgp

import (
	"bytes"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

func protoPtr(p uint8) *uint8  { return &p }
func portPtr(p uint16) *uint16 { return &p }

// RFC 8955 §4.3.1: all packets to 192.0.2.0/24, protocol TCP, destination
// port 25. Component bytes follow the RFC example, with one deviation: the
// port component uses RFC §4.2.2.5 Type 5 (destination-port, 0x05) instead of
// the RFC example's generic Port (Type 4), because flowspec.Rule.DstPort is
// destination-specific and must not match source ports.
func TestEncodeFlowspecGoldenRFC8955Example1(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "192.0.2.0/24", Protocol: protoPtr(6), DstPort: portPtr(25), Action: flowspec.ActionDrop}
	_, nlri, _, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := nlri.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want := []byte{0x0b, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x03, 0x81, 0x06, 0x05, 0x81, 0x19}
	if !bytes.Equal(got, want) {
		t.Fatalf("nlri = %x, want %x", got, want)
	}
}

func TestEncodeFlowspecHostBitNormalization(t *testing.T) {
	// Host bits set in a non-/32 prefix must be masked off for the NLRI.
	rule := flowspec.Rule{Name: "t", Prefix: "198.51.100.7/24", Action: flowspec.ActionDrop}
	_, nlri, _, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, _ := nlri.Serialize()
	want := []byte{0x05, 0x01, 0x18, 0xc6, 0x33, 0x64} // dst 198.51.100.0/24 only, len 0x05 (5 component octets)
	if !bytes.Equal(got, want) {
		t.Fatalf("nlri = %x, want %x", got, want)
	}
}

func TestEncodeFlowspecPlainIPGetsHostMask(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "198.51.100.7", Action: flowspec.ActionDrop}
	key, _, _, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("plain IP must encode as /32: %v", err)
	}
	if want := "fs4|198.51.100.7/32|-|-|-"; key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

func TestEncodeFlowspecMappedV6Rejected(t *testing.T) {
	if _, _, _, err := encodeFlowspec(flowspec.Rule{Name: "t", Prefix: "::ffff:198.51.100.7/128", Action: flowspec.ActionDrop}); err == nil {
		t.Fatal("mapped-v6 /128 must be rejected, not encoded as IPv4 /128")
	}
	if _, _, _, err := encodeFlowspec(flowspec.Rule{Name: "t", Prefix: "::ffff:198.51.100.7", Action: flowspec.ActionDrop}); err != nil {
		t.Fatalf("mapped-v6 plain IP should normalize to IPv4 /32: %v", err)
	}
}

func TestEncodeFlowspecBothPortsGolden(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "192.0.2.0/24", Protocol: protoPtr(17), DstPort: portPtr(53), SrcPort: portPtr(53), Action: flowspec.ActionDrop}
	_, nlri, _, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := nlri.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// dst 192.0.2.0/24 + proto udp(17) + dport 53 + sport 53, RFC type order.
	// Length 0x0e = 14 component octets (5+3+3+3), per RFC §4.1/§4.3.1.
	want := []byte{0x0e, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x03, 0x81, 0x11, 0x05, 0x81, 0x35, 0x06, 0x81, 0x35}
	if !bytes.Equal(got, want) {
		t.Fatalf("nlri = %x, want %x", got, want)
	}
}

func TestEncodeFlowspecRateLimitCommunity(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "198.51.100.7/32", Action: flowspec.ActionRateLimit, RateLimit: 1_000_000}
	_, _, attrs, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Attr type sequence must be Origin(1), NextHop(3), ExtCommunities(16):
	// gobgp's API layer requires Origin + a next-hop on non-withdraw paths.
	if len(attrs) != 3 {
		t.Fatalf("attrs = %d, want 3", len(attrs))
	}
	wantTypes := []bgp.BGPAttrType{
		bgp.BGP_ATTR_TYPE_ORIGIN,
		bgp.BGP_ATTR_TYPE_NEXT_HOP,
		bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES,
	}
	for i, a := range attrs {
		if got := a.GetType(); got != wantTypes[i] {
			t.Fatalf("attr %d type = %d, want %d", i, got, wantTypes[i])
		}
	}
	// Exact-byte assertion only for the ext-communities attr (traffic-rate
	// 1e6 B/s): flags 0xc0 (optional+transitive), type 0x10
	// (ext-communities), len 0x08, then traffic-rate value: type-high 0x80,
	// sub-type 0x06, admin 0x0000, float32 1e6 = 0x49742400.
	serialized, err := attrs[2].Serialize()
	if err != nil {
		t.Fatalf("serialize ext-com: %v", err)
	}
	want := []byte{0xc0, 0x10, 0x08, 0x80, 0x06, 0x00, 0x00, 0x49, 0x74, 0x24, 0x00}
	if !bytes.Equal(serialized, want) {
		t.Fatalf("ext-com attr = %x, want %x", serialized, want)
	}
}

func TestEncodeFlowspecIPv6(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "2001:db8::1/128", Protocol: protoPtr(17), SrcPort: portPtr(53), Action: flowspec.ActionDrop}
	key, _, attrs, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := "fs6|2001:db8::1/128|17|-|53"; key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
	// Same mandatory Origin + NextHop + ext-communities shape as IPv4.
	wantTypes := []bgp.BGPAttrType{
		bgp.BGP_ATTR_TYPE_ORIGIN,
		bgp.BGP_ATTR_TYPE_NEXT_HOP,
		bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES,
	}
	if len(attrs) != len(wantTypes) {
		t.Fatalf("attrs = %d, want %d", len(attrs), len(wantTypes))
	}
	for i, a := range attrs {
		if got := a.GetType(); got != wantTypes[i] {
			t.Fatalf("attr %d type = %d, want %d", i, got, wantTypes[i])
		}
	}
}

func TestEncodeBlackholeGolden(t *testing.T) {
	key, nlri, attrs, err := encodeBlackhole("198.51.100.7/32", "192.0.2.1")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := "rtbh4|198.51.100.7/32"; key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
	got, _ := nlri.Serialize()
	if !bytes.Equal(got, []byte{0x20, 0xc6, 0x33, 0x64, 0x07}) { // victim prefix 198.51.100.7/32
		t.Fatalf("nlri = %x", got)
	}
	foundCommunity := false
	for _, a := range attrs {
		serialized, _ := a.Serialize()
		if bytes.Contains(serialized, []byte{0xff, 0xff, 0x02, 0x9a}) { // 65535:666
			foundCommunity = true
		}
	}
	if !foundCommunity {
		t.Fatalf("blackhole community 65535:666 missing from attrs %v", attrs)
	}
}

func TestEncodeBlackholeInvalidNextHop(t *testing.T) {
	if _, _, _, err := encodeBlackhole("198.51.100.7/32", "not-an-ip"); err == nil {
		t.Fatal("expected error for invalid next-hop")
	}
}
