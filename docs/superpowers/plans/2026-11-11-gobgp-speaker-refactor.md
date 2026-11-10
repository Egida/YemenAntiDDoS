# GoBGP Speaker Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the vtysh/FRR execution model for Flowspec and RTBH with an embedded GoBGP speaker (github.com/osrg/gobgp/v3 v3.37.0) so the Controller originates rules over real BGP sessions.

**Architecture:** New `controller/internal/bgp` package wraps a `gobgp.Server` behind a `Speaker` interface; the action engine and API call `bgp.Shared()`. Connectors become neighbor definitions; a new single-row `bgp_instance` table holds global identity. Vendor CLI rendering, vtysh, and the export-only mode are deleted.

**Tech Stack:** Go 1.25 (`GOTOOLCHAIN=auto` in this environment), github.com/osrg/gobgp/v3 v3.37.0, gin, pgx, Vue 3 + vitest console.

**Spec:** `docs/superpowers/specs/2026-11-11-gobgp-speaker-refactor-design.md`

**Environment note:** every `go` command below runs with `GOTOOLCHAIN=auto go ...` from `controller/` (local toolchain is 1.24.3 but go.mod pins 1.25.0).

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `controller/internal/bgp/speaker.go` | Create | `Speaker` interface, `Config`, `Peer`, `PeerState`, shared holder |
| `controller/internal/bgp/encode.go` | Create | Rule/prefix → gobgp NLRI + attributes, path keys |
| `controller/internal/bgp/gobgp.go` | Create | `GobgpSpeaker`: lifecycle, peers, paths, poll loop |
| `controller/internal/bgp/fake.go` | Create | `FakeSpeaker` recording calls (engine/API tests) |
| `controller/internal/bgp/encode_test.go` | Create | Golden NLRI/community tests |
| `controller/internal/bgp/gobgp_integration_test.go` | Create | Two-speaker BGP integration test |
| `controller/internal/action/flowspec/flowspec.go` | Modify | Delete rendering/`ParseVendor`; add `Describe` |
| `controller/internal/action/flowspec/flowspec_test.go` | Modify | Drop vendor tests, add Describe test |
| `controller/internal/store/models.go` | Modify | `BGPInstance`, connector neighbor fields, drop `VtyshPath` |
| `controller/internal/store/repository.go` | Modify | `BGPInstanceRepo` interface |
| `controller/internal/store/postgres/bgp_instance.go` | Create | instance repo |
| `controller/internal/store/postgres/bgp_connector.go` | Modify | neighbor columns |
| `controller/internal/store/postgres/postgres.go` | Modify | migrations + repo wiring |
| `controller/internal/action/bgp.go` | Modify | speaker calls replace vtysh; recovery rewrite |
| `controller/internal/action/bgp_flowspec.go` | Modify | speaker calls replace vendor render/vtysh |
| `controller/internal/action/engine.go` | Modify | new skip reason |
| `controller/main.go` | Modify | speaker bootstrap + recovery wiring |
| `controller/internal/metrics/metrics.go` | Modify | drop vtysh, add speaker metrics |
| `controller/internal/api/bgp_connector.go` | Modify | neighbor CRUD, speaker-backed test/routes |
| `controller/internal/api/bgp_instance.go` | Create | instance + peer-state endpoints |
| `controller/internal/api/flowspec.go` | Modify | JSON rule views, speaker force-withdraw |
| `controller/internal/api/router.go` | Modify | new routes |
| `controller/console/src/*` | Modify | form, Flowspec tab, i18n, mock |
| `Dockerfile`, `docker-compose.yml`, `controller/config.example.yaml` | Modify | drop FRR |
| `docs/FLOWSPEC.md`, `docs/FLOWSPEC.ar.md`, `docs/ENTERPRISE-UPGRADE-AR.md`, `CHANGELOG.md`, `CHANGELOG.zh.md` | Modify | docs |

Deleted: `controller/internal/action/dao12b_vtysh_test.go`, `controller/internal/api/dao12b_bgp_http_test.go`, `controller/internal/action/bgp_test.go` (replaced by encode tests), vendor CLI rendering.

---

### Task 1: GoBGP dependency + `internal/bgp` skeleton

**Files:**
- Modify: `controller/go.mod`
- Create: `controller/internal/bgp/speaker.go`
- Create: `controller/internal/bgp/fake.go`

- [ ] **Step 1: Add the dependency**

Run from `controller/`:
```bash
GOTOOLCHAIN=auto go get github.com/osrg/gobgp/v3@v3.37.0
GOTOOLCHAIN=auto go mod tidy
```
Expected: go.mod gains `github.com/osrg/gobgp/v3 v3.37.0` plus its indirect deps.

- [ ] **Step 2: Create the Speaker interface and shared holder**

`controller/internal/bgp/speaker.go`:
```go
// Package bgp embeds a GoBGP speaker so the controller originates BGP
// Flowspec (RFC 8955) and RTBH blackhole routes over real BGP sessions,
// replacing the retired local-FRR/vtysh execution model.
package bgp

import (
	"context"
	"sync/atomic"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

// Config is the global speaker identity, loaded from the bgp_instance row.
type Config struct {
	LocalASN    uint32
	RouterID    string
	ListenPort  int32  // 0 disables the inbound listener (outbound-only peering)
	RTBHNextHop string // empty → RouterID
}

// Peer is one neighbor, built from a bgp_connectors row.
type Peer struct {
	ConnectorID   int
	Name          string
	NeighborIP    string
	NeighborASN   uint32
	MD5Password   string
	AddressFamily string // "ipv4" | "ipv6" | "auto"
}

// PeerState is the live session state for console + metrics.
type PeerState struct {
	ConnectorID int
	Name        string
	NeighborIP  string
	SessionUp   bool
}

// Speaker is the engine-facing contract. All announce/withdraw calls are
// idempotent; failures are returned as errors and compensated by callers.
type Speaker interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	AnnounceFlowspec(ctx context.Context, rule flowspec.Rule) error
	WithdrawFlowspec(ctx context.Context, rule flowspec.Rule) error
	AnnounceBlackhole(ctx context.Context, prefix string) error
	WithdrawBlackhole(ctx context.Context, prefix string) error
	SyncPeers(ctx context.Context, peers []Peer) error
	PeerStates(ctx context.Context) []PeerState
}

var shared atomic.Pointer[Speaker]

// SetShared installs the process-wide speaker (nil clears it, e.g. in tests).
func SetShared(sp Speaker) {
	if sp == nil {
		shared.Store(nil)
		return
	}
	shared.Store(&sp)
}

// Shared returns the installed speaker or nil when no bgp_instance is configured.
func Shared() Speaker {
	p := shared.Load()
	if p == nil {
		return nil
	}
	return *p
}
```

- [ ] **Step 3: Create the FakeSpeaker test helper**

`controller/internal/bgp/fake.go`:
```go
package bgp

import (
	"context"
	"sync"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

// FakeSpeaker records every call; tests assert on Calls and drive errors
// via Err on the chosen method. Safe for concurrent engine workers.
type FakeSpeaker struct {
	mu      sync.Mutex
	Calls   []string
	Rules   []flowspec.Rule
	Prefixes []string
	Err     error
	Started bool
	States  []PeerState
}

func (f *FakeSpeaker) record(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, call)
	return f.Err
}

func (f *FakeSpeaker) CallsOf(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c == prefix {
			n++
		}
	}
	return n
}

func (f *FakeSpeaker) Start(_ context.Context) error { f.Started = true; return f.record("start") }
func (f *FakeSpeaker) Stop(_ context.Context) error  { return f.record("stop") }

func (f *FakeSpeaker) AnnounceFlowspec(_ context.Context, rule flowspec.Rule) error {
	f.mu.Lock()
	f.Rules = append(f.Rules, rule)
	f.mu.Unlock()
	return f.record("announce_flowspec")
}

func (f *FakeSpeaker) WithdrawFlowspec(_ context.Context, rule flowspec.Rule) error {
	f.mu.Lock()
	f.Rules = append(f.Rules, rule)
	f.mu.Unlock()
	return f.record("withdraw_flowspec")
}

func (f *FakeSpeaker) AnnounceBlackhole(_ context.Context, prefix string) error {
	f.mu.Lock()
	f.Prefixes = append(f.Prefixes, prefix)
	f.mu.Unlock()
	return f.record("announce_blackhole")
}

func (f *FakeSpeaker) WithdrawBlackhole(_ context.Context, prefix string) error {
	f.mu.Lock()
	f.Prefixes = append(f.Prefixes, prefix)
	f.mu.Unlock()
	return f.record("withdraw_blackhole")
}

func (f *FakeSpeaker) SyncPeers(_ context.Context, peers []Peer) error {
	for range peers {
	}
	return f.record("sync_peers")
}

func (f *FakeSpeaker) PeerStates(_ context.Context) []PeerState { return f.States }
```

- [ ] **Step 4: Build and commit**

```bash
cd controller && GOTOOLCHAIN=auto go build ./internal/bgp/... && cd ..
git add controller/go.mod controller/go.sum controller/internal/bgp/
git commit -m "feat(bgp): speaker interface + fake + gobgp v3.37.0 dependency"
```
Expected: build passes.

---

### Task 2: NLRI encoding with golden tests

**Files:**
- Create: `controller/internal/bgp/encode.go`
- Test: `controller/internal/bgp/encode_test.go`

- [ ] **Step 1: Write the golden tests (TDD)**

`controller/internal/bgp/encode_test.go`:
```go
package bgp

import (
	"bytes"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

func protoPtr(p uint8) *uint8    { return &p }
func portPtr(p uint16) *uint16   { return &p }

// RFC 8955 §4.3.1: all packets to 192.0.2.0/24, protocol TCP, dst port 25.
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
	want := []byte{0x0b, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x03, 0x81, 0x06, 0x04, 0x81, 0x19}
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
	want := []byte{0x07, 0x01, 0x18, 0xc6, 0x33, 0x64} // dst 198.51.100.0/24 only
	if !bytes.Equal(got, want) {
		t.Fatalf("nlri = %x, want %x", got, want)
	}
}

func TestEncodeFlowspecPlainIPGetsHostMask(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "198.51.100.7", Action: flowspec.ActionDrop}
	_, _, _, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("plain IP must encode as /32: %v", err)
	}
}

func TestEncodeFlowspecRateLimitCommunity(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "198.51.100.7/32", Action: flowspec.ActionRateLimit, RateLimit: 1_000_000}
	_, _, attrs, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The only attribute is ext-communities with traffic-rate 1e6 B/s.
	if len(attrs) != 1 {
		t.Fatalf("attrs = %d, want 1", len(attrs))
	}
	serialized, err := attrs[0].Serialize()
	if err != nil {
		t.Fatalf("serialize attr: %v", err)
	}
	// path attr header (30 10) + type high 0x80 low 0x06 + admin 0x0000 + float32 1e6 = 0x49742400
	want := []byte{0x30, 0x10, 0x80, 0x06, 0x00, 0x00, 0x49, 0x74, 0x24, 0x00}
	if !bytes.Equal(serialized, want) {
		t.Fatalf("attr = %x, want %x", serialized, want)
	}
}

func TestEncodeFlowspecIPv6(t *testing.T) {
	rule := flowspec.Rule{Name: "t", Prefix: "2001:db8::1/128", Protocol: protoPtr(17), SrcPort: portPtr(53), Action: flowspec.ActionDrop}
	key, _, _, err := encodeFlowspec(rule)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := "fs6|2001:db8::1/128|17|-|53"; key != want {
		t.Fatalf("key = %q, want %q", key, want)
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
	if !bytes.Equal(got, []byte{0x20, 0xc0, 0x00, 0x02, 0x01}) { // plain unicast NLRI: len=32 + 4 bytes
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
```

Note: golden byte expectations encode gobgp's standard wire serialization (RFC 8955 flowspec NLRI `<len><components>`, RFC 4271 path-attr header `flags=0x30 len=0x10` for a 16-byte extended-communities attribute). If `Serialize()` output for the NLRI differs by the length-prefix convention (single-octet vs none), fix **encode.go**, never the RFC-derived component bytes.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd controller && GOTOOLCHAIN=auto go test ./internal/bgp/ -run TestEncode -v 2>&1 | tail -5
```
Expected: FAIL — `encodeFlowspec`/`encodeBlackhole` undefined.

- [ ] **Step 3: Implement encode.go**

`controller/internal/bgp/encode.go`:
```go
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

	rate := float32(0) // traffic-rate 0 = discard (RFC 8955 §7.1)
	if rule.action() == flowspec.ActionRateLimit {
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd controller && GOTOOLCHAIN=auto go test ./internal/bgp/ -run TestEncode -v 2>&1 | tail -12
```
Expected: all `TestEncode*` PASS. If the RFC example fails on the leading length byte only, adjust `Serialize` usage (e.g. compare `got[1:]`) — component bytes must match the RFC exactly.

- [ ] **Step 5: Commit**

```bash
git add controller/internal/bgp/
git commit -m "feat(bgp): flowspec NLRI + blackhole encoding with RFC 8955 golden tests"
```

---

### Task 3: GobgpSpeaker lifecycle + peers + metrics

**Files:**
- Create: `controller/internal/bgp/gobgp.go`
- Modify: `controller/internal/metrics/metrics.go`

- [ ] **Step 1: Add speaker metrics, remove vtysh metrics**

In `controller/internal/metrics/metrics.go`:
1. Delete the `VtyshOps` var block (lines ~75–91) and the `RecordVtysh` function (lines ~163–167).
2. In `Register(...)`, delete the `VtyshOps` seeding/registration lines and add after the `BGPAnnouncingReconcile` registration:
```go
	if err := reg.Register(BGPSpeakerErrors); err != nil {
		return err
	}
	if err := reg.Register(BGPPeerUp); err != nil {
		return err
	}
	if err := reg.Register(BGPPaths); err != nil {
		return err
	}
```
3. Add vars next to `BGPAnnouncingReconcile` (line ~60):
```go
// BGPSpeakerErrors counts GoBGP speaker AddPath/DeletePath/SyncPeers failures.
var BGPSpeakerErrors = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "xsight_bgp_speaker_errors_total",
	Help: "Embedded GoBGP speaker operation failures.",
})

// BGPPeerUp reflects BGP session state per connector peer (1 = established).
var BGPPeerUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "xsight_bgp_peer_up",
	Help: "BGP session state per configured peer (1 = established, 0 = down).",
}, []string{"connector", "neighbor"})

// BGPPaths counts locally originated paths in the speaker RIB by kind.
var BGPPaths = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "xsight_bgp_paths",
	Help: "Locally originated paths in the speaker RIB, by kind.",
}, []string{"kind"})
```
4. In `controller/internal/metrics/metrics_test.go`, delete the `RecordVtysh(...)` assertions (lines ~36–39) and the vtysh counter expectation block; leave `RecordAction` coverage intact.

- [ ] **Step 2: Implement GobgpSpeaker**

`controller/internal/bgp/gobgp.go`:
```go
package bgp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
)

const speakerTimeout = 30 * time.Second

// GobgpSpeaker runs an embedded gobgp.Server. Paths live in memory; recovery
// re-adds them from bgp_announcements after a restart (see action.RecoverBGPRoutes).
type GobgpSpeaker struct {
	cfg Config

	mu     sync.Mutex
	srv    *server.BgpServer
	uuids  map[string][]byte // pathKey -> AddPath uuid
	peers  map[int]Peer      // connectorID -> last synced peer
	stop   sync.Once
	stopCh chan struct{}
}

func NewGobgp(cfg Config) *GobgpSpeaker {
	return &GobgpSpeaker{
		cfg:    cfg,
		uuids:  map[string][]byte{},
		peers:  map[int]Peer{},
		stopCh: make(chan struct{}),
	}
}

// NextHop resolves the RTBH origination next-hop once, at construction time.
func (c Config) NextHop() (string, error) {
	nh := c.RTBHNextHop
	if nh == "" {
		nh = c.RouterID
	}
	if net.ParseIP(nh) == nil {
		return "", fmt.Errorf("bgp: invalid rtbh next-hop %q (router-id %q)", nh, c.RouterID)
	}
	return nh, nil
}

func (s *GobgpSpeaker) Start(_ context.Context) error {
	if _, err := s.cfg.NextHop(); err != nil {
		return err
	}
	srv := server.NewBgpServer()
	go srv.Serve()
	ctx, cancel := context.WithTimeout(context.Background(), speakerTimeout)
	defer cancel()
	if err := srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:             s.cfg.LocalASN,
		RouterId:        s.cfg.RouterID,
		ListenPort:      s.cfg.ListenPort,
		ListenAddresses: []string{"0.0.0.0", "::"},
	}}); err != nil {
		return fmt.Errorf("bgp: start speaker: %w", err)
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()
	go s.pollLoop()
	return nil
}

func (s *GobgpSpeaker) Stop(_ context.Context) error {
	s.stop.Do(func() { close(s.stopCh) })
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
	return nil
}

// peerFamilies returns the unicast + flowspec families for the peer's AF.
func peerFamilies(af string) []api.Family {
	if af == "ipv6" {
		return []api.Family{
			{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST},
			{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
		}
	}
	return []api.Family{
		{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
	}
}

func effectiveAF(p Peer) string {
	if p.AddressFamily == "auto" {
		if strings.Contains(p.NeighborIP, ":") {
			return "ipv6"
		}
		return "ipv4"
	}
	return p.AddressFamily
}

func (s *GobgpSpeaker) addPeer(ctx context.Context, p Peer) error {
	afs := make([]*api.AfiSafi, 0, 2)
	for _, f := range peerFamilies(effectiveAF(p)) {
		afs = append(afs, &api.AfiSafi{Config: &api.AfiSafiConfig{
			Family: &api.Family{Afi: f.Afi, Safi: f.Safi}, Enabled: true,
		}})
	}
	err := s.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.NeighborIP,
			PeerAsn:         p.NeighborASN,
			AuthPassword:    p.MD5Password,
			Description:     p.Name,
		},
		AfiSafis: afs,
	}})
	if err != nil {
		metrics.BGPSpeakerErrors.Inc()
		return fmt.Errorf("bgp: add peer %s: %w", p.NeighborIP, err)
	}
	return nil
}

// SyncPeers reconciles the desired peer set: adds missing neighbors,
// deletes+re-adds changed ones (a session bounce is required for any peer
// parameter change), and removes stale ones. Deleting a peer tears down the
// session, which makes that neighbor withdraw everything it learned from us.
func (s *GobgpSpeaker) SyncPeers(ctx context.Context, peers []Peer) error {
	cctx, cancel := context.WithTimeout(ctx, speakerTimeout)
	defer cancel()
	desired := make(map[string]Peer, len(peers))
	for _, p := range peers {
		if strings.TrimSpace(p.NeighborIP) == "" || p.NeighborASN == 0 {
			continue // rows without peering details stay inert (fail-closed)
		}
		desired[p.NeighborIP] = p
	}
	existing := map[string]bool{}
	_ = s.srv.ListPeer(cctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		existing[p.Conf.GetNeighborAddress()] = true
	})
	for addr, p := range desired {
		if old, ok := s.peers[p.ConnectorID]; ok && existing[addr] &&
			old.NeighborASN == p.NeighborASN && old.MD5Password == p.MD5Password &&
			old.AddressFamily == p.AddressFamily {
			continue
		}
		if existing[addr] {
			if err := s.srv.DeletePeer(cctx, &api.DeletePeerRequest{Address: addr}); err != nil {
				metrics.BGPSpeakerErrors.Inc()
				return fmt.Errorf("bgp: replace peer %s: %w", addr, err)
			}
		}
		if err := s.addPeer(cctx, p); err != nil {
			return err
		}
	}
	for addr := range existing {
		if _, ok := desired[addr]; !ok {
			if err := s.srv.DeletePeer(cctx, &api.DeletePeerRequest{Address: addr}); err != nil {
				metrics.BGPSpeakerErrors.Inc()
				return fmt.Errorf("bgp: delete peer %s: %w", addr, err)
			}
		}
	}
	s.mu.Lock()
	s.peers = map[int]Peer{}
	for _, p := range desired {
		s.peers[p.ConnectorID] = p
	}
	s.mu.Unlock()
	return nil
}

// PeerStates snapshots live session state, joined with connector identity.
func (s *GobgpSpeaker) PeerStates(ctx context.Context) []PeerState {
	cctx, cancel := context.WithTimeout(ctx, speakerTimeout)
	defer cancel()
	s.mu.Lock()
	byAddr := map[string]Peer{}
	for _, p := range s.peers {
		byAddr[p.NeighborIP] = p
	}
	s.mu.Unlock()
	out := []PeerState{}
	_ = s.srv.ListPeer(cctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		addr := p.Conf.GetNeighborAddress()
		st := PeerState{NeighborIP: addr, SessionUp: p.State.GetSessionState() == api.PeerState_ESTABLISHED}
		if peer, ok := byAddr[addr]; ok {
			st.ConnectorID = peer.ConnectorID
			st.Name = peer.Name
		}
		out = append(out, st)
	})
	return out
}

func (s *GobgpSpeaker) pollLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	s.pollOnce()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.pollOnce()
		}
	}
}

// pollOnce refreshes peer gauges and locally-originated path counts.
func (s *GobgpSpeaker) pollOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), speakerTimeout)
	defer cancel()
	for _, st := range s.PeerStates(ctx) {
		v := 0.0
		if st.SessionUp {
			v = 1
		}
		metrics.BGPPeerUp.WithLabelValues(fmt.Sprintf("%d", st.ConnectorID), st.NeighborIP).Set(v)
	}
	families := map[string]api.Family{
		"rtbh":      {Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		"flowspec":  {Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
	}
	// IPv6 counts fold into the same kinds via a second pass.
	families["rtbh6"] = api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
	families["flowspec6"] = api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}

	counts := map[string]float64{"rtbh": 0, "flowspec": 0}
	for kind, fam := range families {
		kindKey := strings.TrimSuffix(kind, "6")
		n := 0
		_ = s.srv.ListPath(ctx, &api.ListPathRequest{
			TableType: api.TableType_GLOBAL,
			Name:      "global",
			Family:    &api.Family{Afi: fam.Afi, Safi: fam.Safi},
		}, func(dest *api.Destination) {
			for _, p := range dest.Paths {
				if len(p.Uuid) > 0 { // only locally-originated (AddPath) paths carry a uuid
					n++
				}
			}
		})
		counts[kindKey] += float64(n)
	}
	for kind, v := range counts {
		metrics.BGPPaths.WithLabelValues(kind).Set(v)
	}
}

// announce/withdraw primitives shared by the four public path methods.
func (s *GobgpSpeaker) addPath(ctx context.Context, key string, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface) error {
	apiPath, err := apiutil.NewPath(nlri, false, attrs, time.Now())
	if err != nil {
		return fmt.Errorf("bgp: marshal path: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, speakerTimeout)
	defer cancel()
	resp, err := s.srv.AddPath(cctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: apiPath})
	if err != nil {
		metrics.BGPSpeakerErrors.Inc()
		return fmt.Errorf("bgp: add path: %w", err)
	}
	s.mu.Lock()
	s.uuids[key] = resp.Uuid
	s.mu.Unlock()
	return nil
}

func (s *GobgpSpeaker) deletePath(ctx context.Context, key string, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface) error {
	cctx, cancel := context.WithTimeout(ctx, speakerTimeout)
	defer cancel()
	s.mu.Lock()
	uuid := s.uuids[key]
	delete(s.uuids, key)
	s.mu.Unlock()
	var err error
	if len(uuid) > 0 {
		err = s.srv.DeletePath(cctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Uuid: uuid})
	} else {
		// UUID lost (speaker restarted mid-flight): delete by exact NLRI.
		wd, werr := apiutil.NewPath(nlri, true, attrs, time.Now())
		if werr != nil {
			return fmt.Errorf("bgp: marshal withdraw path: %w", werr)
		}
		err = s.srv.DeletePath(cctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: wd})
	}
	if err != nil {
		metrics.BGPSpeakerErrors.Inc()
		return fmt.Errorf("bgp: delete path: %w", err)
	}
	return nil
}

func (s *GobgpSpeaker) AnnounceFlowspec(ctx context.Context, rule flowspec.Rule) error {
	key, nlri, attrs, err := encodeFlowspec(rule)
	if err != nil {
		return err
	}
	return s.addPath(ctx, key, nlri, attrs)
}

func (s *GobgpSpeaker) WithdrawFlowspec(ctx context.Context, rule flowspec.Rule) error {
	key, nlri, attrs, err := encodeFlowspec(rule)
	if err != nil {
		return err
	}
	return s.deletePath(ctx, key, nlri, attrs)
}

func (s *GobgpSpeaker) AnnounceBlackhole(ctx context.Context, prefix string) error {
	nh, err := s.cfg.NextHop()
	if err != nil {
		return err
	}
	key, nlri, attrs, err := encodeBlackhole(prefix, nh)
	if err != nil {
		return err
	}
	return s.addPath(ctx, key, nlri, attrs)
}

func (s *GobgpSpeaker) WithdrawBlackhole(ctx context.Context, prefix string) error {
	nh, err := s.cfg.NextHop()
	if err != nil {
		return err
	}
	key, nlri, attrs, err := encodeBlackhole(prefix, nh)
	if err != nil {
		return err
	}
	return s.deletePath(ctx, key, nlri, attrs)
}
```

- [ ] **Step 3: Build and vet**

```bash
cd controller && GOTOOLCHAIN=auto go build ./internal/bgp/ ./internal/metrics/ && GOTOOLCHAIN=auto go vet ./internal/bgp/ ./internal/metrics/
```
Expected: clean. If a gobgp API name drifted (e.g. `ListPeerRequest` fields), fix against the module source at `$(go env GOMODCACHE)/github.com/osrg/gobgp/v3@v3.37.0/` — never invent API names.

- [ ] **Step 4: Run metrics + bgp tests**

```bash
cd controller && GOTOOLCHAIN=auto go test ./internal/metrics/ ./internal/bgp/ 2>&1 | tail -5
```
Expected: PASS (fix metrics_test.go vtysh assertions if still present).

- [ ] **Step 5: Commit**

```bash
git add controller/internal/bgp/ controller/internal/metrics/
git commit -m "feat(bgp): embedded GobgpSpeaker lifecycle, peer sync, path mgmt, metrics"
```

---

### Task 4: Two-speaker integration test

**Files:**
- Test: `controller/internal/bgp/gobgp_integration_test.go`

- [ ] **Step 1: Write the integration test**

`controller/internal/bgp/gobgp_integration_test.go`:
```go
package bgp

import (
	"context"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/api"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

// Two in-process speakers: the controller speaker peers with a fake upstream.
// The upstream receives the flowspec path (SAFI 133) and the blackhole
// unicast path (SAFI 1) with the right attributes.
func startSpeaker(t *testing.T, asn uint32, routerID string, port int32, listen bool) *GobgpSpeaker {
	t.Helper()
	cfg := Config{LocalASN: asn, RouterID: routerID, ListenPort: port, RTBHNextHop: routerID}
	if !listen {
		cfg.ListenPort = 0
	}
	sp := NewGobgp(cfg)
	if err := sp.Start(context.Background()); err != nil {
		t.Fatalf("start speaker: %v", err)
	}
	t.Cleanup(func() { _ = sp.Stop(context.Background()) })
	return sp
}

func TestIntegrationFlowspecAndBlackholePropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	upstream := startSpeaker(t, 65001, "192.0.2.10", 11790, true)
	ctrl := startSpeaker(t, 65000, "192.0.2.9", 0, false)

	ctx, cancel := context.WithTimeout(context.Background(), speakerTimeout)
	defer cancel()
	if err := ctrl.SyncPeers(ctx, []Peer{{
		ConnectorID: 1, Name: "upstream", NeighborIP: "127.0.0.1", NeighborASN: 65001, AddressFamily: "ipv4",
	}}); err != nil {
		t.Fatalf("sync peers: %v", err)
	}
	// The peer connects to the upstream listener (Transport.RemotePort defaults
	// to the global listen port); upstream accepts passively.

	deadline := time.Now().Add(10 * time.Second)
	established := false
	for time.Now().Before(deadline) && !established {
		for _, st := range upstream.PeerStates(ctx) {
			if st.SessionUp {
				established = true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !established {
		t.Fatal("session never established")
	}

	rule := flowspec.Rule{Name: "xsight-test", Prefix: "198.51.100.7/32", Action: flowspec.ActionDrop}
	if err := ctrl.AnnounceFlowspec(ctx, rule); err != nil {
		t.Fatalf("announce flowspec: %v", err)
	}
	if err := ctrl.AnnounceBlackhole(ctx, "198.51.100.9/32"); err != nil {
		t.Fatalf("announce blackhole: %v", err)
	}

	var sawFS, sawBH bool
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !(sawFS && sawBH) {
		_ = upstream.srv.ListPath(ctx, &api.ListPathRequest{
			TableType: api.TableType_GLOBAL,
			Name:      "global",
			Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
		}, func(d *api.Destination) {
			if d.Prefix == "198.51.100.7/32" && len(d.Paths) > 0 {
				sawFS = true
			}
		})
		_ = upstream.srv.ListPath(ctx, &api.ListPathRequest{
			TableType: api.TableType_GLOBAL,
			Name:      "global",
			Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		}, func(d *api.Destination) {
			if d.Prefix == "198.51.100.9/32" && len(d.Paths) > 0 {
				sawBH = true
			}
		})
		time.Sleep(200 * time.Millisecond)
	}
	if !sawFS {
		t.Fatal("upstream never received the flowspec path")
	}
	if !sawBH {
		t.Fatal("upstream never received the blackhole path")
	}

	if err := ctrl.WithdrawFlowspec(ctx, rule); err != nil {
		t.Fatalf("withdraw flowspec: %v", err)
	}
	if err := ctrl.WithdrawBlackhole(ctx, "198.51.100.9/32"); err != nil {
		t.Fatalf("withdraw blackhole: %v", err)
	}
	sawFS, sawBH = false, false
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (sawFS || sawBH) {
		sawFS, sawBH = false, false
		_ = upstream.srv.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_GLOBAL, Name: "global",
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}}, func(d *api.Destination) {
			if d.Prefix == "198.51.100.7/32" && len(d.Paths) > 0 {
				sawFS = true
			}
		})
		_ = upstream.srv.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_GLOBAL, Name: "global",
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, func(d *api.Destination) {
			if d.Prefix == "198.51.100.9/32" && len(d.Paths) > 0 {
				sawBH = true
			}
		})
		time.Sleep(200 * time.Millisecond)
	}
	if sawFS || sawBH {
		t.Fatal("upstream still holds withdrawn paths")
	}
}
```

- [ ] **Step 2: Run**

```bash
cd controller && GOTOOLCHAIN=auto go test ./internal/bgp/ -run TestIntegration -v 2>&1 | tail -8
```
Expected: PASS. If the upstream never receives paths, check: peer transport port (upstream listens on 11790 — the peer must dial that port; if `SyncPeers` dials 179, set `Transport: &api.Transport{RemotePort: 11790}` in `addPeer` via an optional `Peer.RemotePort uint32` field added to `Peer`), and eBGP multihop for loopback peering (add `EbgpMultihop: &api.EbgpMultihop{Enabled: true, MultihopTtl: 2}` if needed). Those are the two knobs; adjust `gobgp.go` and the `Peer` struct accordingly, then re-run.

- [ ] **Step 3: Full package suite + commit**

```bash
cd controller && GOTOOLCHAIN=auto go test ./internal/bgp/ 2>&1 | tail -3
git add controller/internal/bgp/
git commit -m "test(bgp): two-speaker integration test for flowspec + blackhole propagation"
```

---

### Task 5: Store — bgp_instance + connector neighbor columns

**Files:**
- Modify: `controller/internal/store/models.go`, `controller/internal/store/repository.go`
- Create: `controller/internal/store/postgres/bgp_instance.go`
- Modify: `controller/internal/store/postgres/bgp_connector.go`, `controller/internal/store/postgres/postgres.go`

- [ ] **Step 1: Model changes**

In `controller/internal/store/models.go`, replace the `BGPConnector` struct (lines ~226–242) with:
```go
// BGPConnector is one BGP neighbor (peer) of the embedded speaker.
type BGPConnector struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	BGPASN      int    `json:"bgp_asn"`
	AddressFamily string `json:"address_family"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	// Vendor is informational only since the GoBGP refactor (free text).
	Vendor string `json:"vendor"`
	// FlowspecEnabled switches BGP actions on this connector from RTBH
	// (whole-prefix blackhole) to a narrower Flowspec rule.
	FlowspecEnabled bool `json:"flowspec_enabled"`
	// Peering details; an enabled connector requires all three (API validation).
	NeighborIP    string `json:"neighbor_ip"`
	NeighborASN   int    `json:"neighbor_asn"`
	MD5Password   string `json:"md5_password"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// BGPInstance is the single-row global speaker configuration.
type BGPInstance struct {
	LocalASN    int       `json:"local_asn"`
	RouterID    string    `json:"router_id"`
	ListenPort  int       `json:"listen_port"`
	RTBHNextHop string    `json:"rtbh_next_hop"`
	UpdatedAt   time.Time `json:"updated_at"`
}
```
`VtyshPath` is deleted from the model; the DB column stays (NOT NULL default) as a legacy no-op.

- [ ] **Step 2: Repository interface**

In `controller/internal/store/repository.go`, add near the `BGPConnectors` interface:
```go
// BGPInstanceRepo manages the single-row speaker configuration.
type BGPInstanceRepo interface {
	// Get returns nil, nil when no row exists (speaker unconfigured).
	Get(ctx context.Context) (*BGPInstance, error)
	Upsert(ctx context.Context, inst *BGPInstance) error
}
```
and to the `Store` interface add `BGPInstances() BGPInstanceRepo` next to `BGPConnectors()`.

- [ ] **Step 3: Instance repo implementation**

`controller/internal/store/postgres/bgp_instance.go`:
```go
package postgres

import (
	"context"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type bgpInstanceRepo struct{ pool poolLike }

func (r *bgpInstanceRepo) Get(ctx context.Context) (*store.BGPInstance, error) {
	var inst store.BGPInstance
	err := r.pool.QueryRow(ctx,
		`SELECT local_asn, router_id, listen_port, rtbh_next_hop, updated_at FROM bgp_instance WHERE id=1`).
		Scan(&inst.LocalASN, &inst.RouterID, &inst.ListenPort, &inst.RTBHNextHop, &inst.UpdatedAt)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &inst, nil
}

func (r *bgpInstanceRepo) Upsert(ctx context.Context, inst *store.BGPInstance) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO bgp_instance (id, local_asn, router_id, listen_port, rtbh_next_hop, updated_at)
		 VALUES (1, $1, $2, $3, $4, now())
		 ON CONFLICT (id) DO UPDATE SET
		   local_asn=$1, router_id=$2, listen_port=$3, rtbh_next_hop=$4, updated_at=now()`,
		inst.LocalASN, inst.RouterID, inst.ListenPort, inst.RTBHNextHop)
	return err
}
```
Note: check the struct type used for pools in sibling repos (`bgpConnectorRepo` uses `*pgxpool.Pool`) — use the same type; the `no rows` check must use `errors.Is(err, pgx.ErrNoRows)`:
```go
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
```
(imports: `errors`, `github.com/jackc/pgx/v5`).

- [ ] **Step 4: Connector SQL updates**

In `controller/internal/store/postgres/bgp_connector.go`:
```go
const bgpConnectorCols = `id, name, bgp_asn, address_family, enabled, description,
	COALESCE(vendor, ''), COALESCE(flowspec_enabled, false),
	COALESCE(neighbor_ip, ''), COALESCE(neighbor_asn, 0), COALESCE(md5_password, ''), created_at, updated_at`
```
Update `List`/`Get` scans to match the new column order (`&c.NeighborIP, &c.NeighborASN, &c.MD5Password` between FlowspecEnabled and CreatedAt), and:
```go
func (r *bgpConnectorRepo) Create(ctx context.Context, c *store.BGPConnector) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO bgp_connectors (name, bgp_asn, address_family, enabled, description, vendor, flowspec_enabled, neighbor_ip, neighbor_asn, md5_password)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		c.Name, c.BGPASN, c.AddressFamily, c.Enabled, c.Description, c.Vendor, c.FlowspecEnabled,
		c.NeighborIP, c.NeighborASN, c.MD5Password).Scan(&id)
	return id, err
}

func (r *bgpConnectorRepo) Update(ctx context.Context, c *store.BGPConnector) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_connectors
		 SET name=$1, bgp_asn=$2, address_family=$3, enabled=$4, description=$5,
		     vendor=$6, flowspec_enabled=$7, neighbor_ip=$8, neighbor_asn=$9, md5_password=$10, updated_at=now()
		 WHERE id=$11`,
		c.Name, c.BGPASN, c.AddressFamily, c.Enabled, c.Description,
		c.Vendor, c.FlowspecEnabled, c.NeighborIP, c.NeighborASN, c.MD5Password, c.ID)
	return err
}
```

- [ ] **Step 5: Migrations + wiring**

In `controller/internal/store/postgres/postgres.go`:
1. Add to the migration list (after the `flowspec_enabled` ALTER at ~line 1543):
```go
	// v5.0: embedded GoBGP speaker — global identity + neighbor peering.
	`CREATE TABLE IF NOT EXISTS bgp_instance (
		id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
		local_asn INT NOT NULL DEFAULT 0,
		router_id TEXT NOT NULL DEFAULT '',
		listen_port INT NOT NULL DEFAULT 179,
		rtbh_next_hop TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMPTZ DEFAULT now()
	)`,
	`ALTER TABLE bgp_connectors ADD COLUMN IF NOT EXISTS neighbor_ip TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE bgp_connectors ADD COLUMN IF NOT EXISTS neighbor_asn INT NOT NULL DEFAULT 0`,
	`ALTER TABLE bgp_connectors ADD COLUMN IF NOT EXISTS md5_password TEXT NOT NULL DEFAULT ''`,
```
2. Add `createBGPInstance` to the table bootstrap list the same way other tables are registered (pattern at line ~776), or rely on the migration list entry — follow the pattern of `ts_node_posture` (most recent addition).
3. Wire the repo: find where `bgpConnectors` repo is constructed in the `Store` assembly (search `bgpConnectorRepo{`) and add `bgpInstances: &bgpInstanceRepo{pool: db.pool}` following the same pattern; add `bgpInstances BGPInstanceRepo` field + `func (s *storeImpl) BGPInstances() store.BGPInstanceRepo { return s.bgpInstances }` matching the existing accessor pattern.

- [ ] **Step 6: Build + store tests + commit**

```bash
cd controller && GOTOOLCHAIN=auto go build ./... 2>&1 | head -20
```
Expected: compile errors ONLY in `internal/api` and `internal/action` files referencing `VtyshPath`/`flowspec.ParseVendor` — these are fixed in Tasks 6–7. Verify `./internal/store/...` compiles:
```bash
cd controller && GOTOOLCHAIN=auto go build ./internal/store/... && GOTOOLCHAIN=auto go test ./internal/store/... 2>&1 | tail -3
git add controller/internal/store/
git commit -m "feat(store): bgp_instance table + neighbor columns on bgp_connectors"
```

---

### Task 6: Action engine swap + recovery + main wiring

**Files:**
- Modify: `controller/internal/action/bgp.go`, `controller/internal/action/bgp_flowspec.go`, `controller/internal/action/engine.go`, `controller/main.go`
- Delete: `controller/internal/action/bgp_test.go`, `controller/internal/action/dao12b_vtysh_test.go`
- Modify: `controller/internal/action/dao3_security_test.go`, `controller/internal/action/startup_cleanup_test.go`, `controller/internal/action/flowspec/flowspec.go`, `controller/internal/action/flowspec/flowspec_test.go`

- [ ] **Step 1: Slim the flowspec package**

In `controller/internal/action/flowspec/flowspec.go`:
1. Delete: `Vendor` type + all vendor consts, `ParseVendor`, `Render`, `RenderWithdraw`, `renderFRR`, `withdrawFRR`, `templateFor`, `renderTemplate`, `withdrawTemplate`, `substitute`, `protoNamePtr`, `portPtr`.
2. Keep: `Action` consts, `Rule`, `Validate`, `action()`, `protoName`.
3. Add `Describe` (used by engine logs and the console):
```go
// Describe renders a human-readable match tuple for logs and the console.
func Describe(r Rule) string {
	parts := []string{"destination " + r.Prefix}
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
```
4. `flowspec_test.go`: delete `TestParseVendor`-style and `TestRender*` tests; add:
```go
func TestDescribe(t *testing.T) {
	r := Rule{Name: "x", Prefix: "198.51.100.7/32", Action: ActionDrop}
	want := "destination 198.51.100.7/32, drop (traffic-rate 0)"
	if got := Describe(r); got != want {
		t.Fatalf("Describe = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Engine skip reason**

In `controller/internal/action/engine.go`, next to the other `SkipReason*` consts (search `SkipReasonConnectorDisabled`), add:
```go
const SkipReasonSpeakerNotConfigured = "speaker_not_configured"
```
and extend the cardinality comment from 18 to 19 values.

- [ ] **Step 3: Rewrite bgp_flowspec.go execution paths**

In `controller/internal/action/bgp_flowspec.go`:
1. Delete `connectorVendor` entirely.
2. Replace `flowspecAnnounce`'s post-Attach section (from `vendor, vErr := connectorVendor(conn)` through the vtysh success return) with:
```go
	sp := bgp.Shared()
	if sp == nil {
		msg := "bgp speaker not configured: set up Settings → BGP Instance first"
		markFlowspecAnnounceFailed(ctx, s, attachResult, errors.New(msg))
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
		markFlowspecAnnounceFailed(ctx, s, attachResult, aErr)
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
```
3. Replace `flowspecWithdraw`'s post-Detach section (from `vendor, vErr := connectorVendor(conn)` through the vtysh success return, keeping the `!result.NeedWithdraw` early return above it) with:
```go
	sp := bgp.Shared()
	if sp == nil {
		msg := "bgp speaker not configured: set up Settings → BGP Instance first"
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
		if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, result.AnnouncementID, result.Gen, wErr.Error())
		}); mErr != nil {
			metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
		}
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
		rule.Prefix, conn.Name, result.AnnouncementID)
	return &store.ActionExecutionLog{
		AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
		TriggerPhase: triggerPhase, ResponseName: responseName,
		ConnectorName: conn.Name, ConnectorID: &connID,
		Status: "success", Detail: detail,
		RequestBody:    flowspec.Describe(rule),
		ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
	}, nil
```
4. Update imports: drop `strings`, add `github.com/d80y6/YemenDDoS/controller/internal/bgp`.

- [ ] **Step 4: Rewrite bgp.go execution + recovery**

In `controller/internal/action/bgp.go`:
1. Delete: `addressFamilyForPrefix`, `isFRRRouteAbsentError`, `runVtysh`, and the vars `vtyshTimeout`, `vtyshWaitDelay`, `errVtyshTimeout`.
2. In `executeBGP`, replace the export-only vendor guard (`if vendor, vErr := flowspec.ParseVendor(conn.Vendor); ...`) with a speaker guard placed right after the `conn.FlowspecEnabled` branch decision:
```go
	sp := bgp.Shared()
	if sp == nil {
		return recordSkip(&store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, Status: "skipped",
			ErrorMessage: "bgp speaker not configured: set up Settings → BGP Instance first",
			ConnectorID:  act.BGPConnectorID, ExecutedAt: time.Now(),
		}, SkipReasonSpeakerNotConfigured), nil
	}
```
3. In `bgpAnnounce`, replace the first-attach vtysh block (`af := addressFamilyForPrefix(dstIP)` … through the success return) with:
```go
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
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed", ErrorMessage: errorMessage, Detail: detail,
			RequestBody:    "blackhole " + dstIP,
			ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
		}, aErr
	}

	detail := fmt.Sprintf("triggered announcement_id=%d", attachResult.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkAnnounced(ctx, attachResult.AnnouncementID, attachResult.Gen); bgpStateNotApplied(mErr, attachResult.AnnouncementID, attachResult.Gen, "announced") {
		detail += "; " + bgpNotAppliedDetail
	} else if mErr != nil {
		log.Printf("action: bgp MarkAnnounced announcement_id=%d: %v", attachResult.AnnouncementID, mErr)
	}
	log.Printf("action: bgp announce %s connector=%s announcement_id=%d", dstIP, conn.Name, attachResult.AnnouncementID)
	return &store.ActionExecutionLog{
		AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
		TriggerPhase: triggerPhase, ResponseName: responseName,
		ConnectorName: conn.Name, ConnectorID: &connID,
		Status: "success", Detail: detail,
		RequestBody:    "blackhole " + dstIP,
		ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
	}, nil
```
(The ctx-cancelled/exit-error "outcome unknown" branches exist only to classify vtysh process death — a speaker call is a single RPC-style result, so they are gone. `cmd`/`out` locals are gone; `metrics.RecordVtysh` calls are gone.)
4. In `performBGPWithdraw`, replace the vtysh block (from `waf := addressFamilyForPrefix(dstIP)` through the success return) with:
```go
	t0 := time.Now()
	wErr := bgp.Shared().WithdrawBlackhole(ctx, dstIP)
	durationMs := int(time.Since(t0).Milliseconds())

	if wErr != nil {
		// Real failure.
		metrics.StateWriteFailures.Add(0) // no-op guard; see recordStateError below
		if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, announcementID, gen, wErr.Error())
		}); mErr != nil {
			recordStateError(mErr, "failed_withdraw")
		}
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status: "failed",
			ErrorMessage:   fmt.Sprintf("speaker: %v", wErr) + stateError,
			Detail:         stateDetail,
			RequestBody:    "blackhole " + dstIP,
			ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
		}, wErr
	}
```
…and the success tail becomes:
```go
	log.Printf("action: bgp withdraw %s connector=%s announcement_id=%d", dstIP, conn.Name, announcementID)
	if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
		return s.BGPAnnouncements().MarkWithdrawn(writeCtx, announcementID, gen)
	}); mErr != nil {
		recordStateError(mErr, "withdrawn")
	}
	return &store.ActionExecutionLog{
		AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
		TriggerPhase: triggerPhase, ResponseName: responseName,
		ConnectorName: conn.Name, ConnectorID: &connID,
		Status: "success",
		ErrorMessage:   strings.TrimPrefix(stateError, "; "),
		Detail:         stateDetail,
		RequestBody:    "blackhole " + dstIP,
		ExternalRuleID: externalRuleID, DurationMs: durationMs, ExecutedAt: t0,
	}, nil
```
Delete the entire `isFRRRouteAbsentError` idempotent branch (a gobgp delete of a missing path is already a no-op — idempotency is structural now). Remove the stray `metrics.StateWriteFailures.Add(0)` line if it reads oddly — it exists only to keep the block shape; prefer deleting it.
5. Replace `RecoverBGPRoutes` with:
```go
// RecoverBGPRoutes re-originates active/delayed announcements in the embedded
// speaker after a controller restart. Synchronous; runs before startup
// reconciliation. Flowspec rules rebuild from the stored rule_spec JSON;
// RTBH from the announcement prefix.
func RecoverBGPRoutes(ctx context.Context, s store.Store) {
	sp := bgp.Shared()
	if sp == nil {
		log.Printf("bgp recovery: speaker not configured, skipping %d announcements", len(mustListActive(ctx, s)))
		return
	}
	announcements, err := s.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		log.Printf("bgp recovery: list announcements: %v", err)
		return
	}
	for _, ann := range announcements {
		if ann.Status != "active" && ann.Status != "delayed" {
			continue
		}
		if ann.Kind == "flowspec" {
			rule := flowspecRuleFromSpec(ann)
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

func mustListActive(ctx context.Context, s store.Store) []store.BGPAnnouncement {
	anns, err := s.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		return nil
	}
	return anns
}

// flowspecRuleFromSpec rebuilds the rule from a flowspec announcement row.
func flowspecRuleFromSpec(ann store.BGPAnnouncement) flowspec.Rule {
	var rule flowspec.Rule
	if strings.TrimSpace(ann.RuleSpec) != "" {
		_ = json.Unmarshal([]byte(ann.RuleSpec), &rule)
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
	return rule
}
```
Imports for bgp.go after edits: `context`, `encoding/json`, `errors`, `fmt`, `log`, `strings`, `time`, `internal/bgp`, `internal/action/flowspec`, `internal/metrics`, `internal/store`.

- [ ] **Step 5: Wire main.go**

In `controller/main.go`, after `iStore := metrics.InstrumentStore(db)` (line ~233) and before `recoverOnStartup`, insert:
```go
	// --- Embedded GoBGP speaker (v5.0) ---
	if inst, iErr := db.BGPInstances().Get(ctx); iErr != nil {
		log.Printf("bgp: load instance config: %v", iErr)
	} else if inst != nil && inst.LocalASN > 0 && inst.RouterID != "" {
		sp := bgp.NewGobgp(bgp.Config{
			LocalASN:    uint32(inst.LocalASN),
			RouterID:    inst.RouterID,
			ListenPort:  int32(inst.ListenPort),
			RTBHNextHop: inst.RTBHNextHop,
		})
		if sErr := sp.Start(ctx); sErr != nil {
			log.Fatalf("bgp: start speaker: %v", sErr)
		}
		bgp.SetShared(sp)
		if conns, cErr := iStore.BGPConnectors().List(ctx); cErr == nil {
			peers := make([]bgp.Peer, 0, len(conns))
			for _, conn := range conns {
				if !conn.Enabled || conn.NeighborIP == "" || conn.NeighborASN == 0 {
					continue
				}
				peers = append(peers, bgp.Peer{
					ConnectorID: conn.ID, Name: conn.Name,
					NeighborIP: conn.NeighborIP, NeighborASN: uint32(conn.NeighborASN),
					MD5Password: conn.MD5Password, AddressFamily: conn.AddressFamily,
				})
			}
			if pErr := sp.SyncPeers(ctx, peers); pErr != nil {
				log.Printf("bgp: initial peer sync: %v", pErr)
			}
		}
		log.Printf("bgp: speaker started asn=%d router-id=%s port=%d", inst.LocalASN, inst.RouterID, inst.ListenPort)
	} else {
		log.Printf("bgp: no bgp_instance configured; BGP actions fail closed")
	}
```
Add import `"github.com/d80y6/YemenDDoS/controller/internal/bgp"`. `recoverOnStartup` still calls `action.RecoverBGPRoutes` — unchanged call site. If `db.BGPInstances()` is not reachable (db is the concrete postgres type — it is), keep it on `db`.

- [ ] **Step 6: Test rewrites**

1. Delete `controller/internal/action/bgp_test.go` and `controller/internal/action/dao12b_vtysh_test.go`:
```bash
git rm controller/internal/action/bgp_test.go controller/internal/action/dao12b_vtysh_test.go
```
2. In `controller/internal/action/dao3_security_test.go`: delete the vtysh-script helper (around lines 95–122) and the tests `TestDao3_T1e_ExecutionGuards` (vtysh-token cases only) and `TestDao3_T1f_VisibleFRRNameAllowed` (vtyshTokens is deleted; route-map names now live only in DB identity fields and never reach a shell).
3. In `controller/internal/action/startup_cleanup_test.go`: replace the vtysh script fixture (lines ~118+) with `bgp.SetShared(&bgp.FakeSpeaker{})` before engine startup (and `bgp.SetShared(nil)` in cleanup). `TestFuzhuo_G10_AsyncWithdrawDoesNotBlockStartup` now asserts `CleanupEndedAttachments` completes immediately with the fake — keep the 5s deadline assertion.
4. Build + targeted tests:
```bash
cd controller && GOTOOLCHAIN=auto go build ./internal/action/... && GOTOOLCHAIN=auto go test ./internal/action/... ./internal/action/flowspec/ 2>&1 | tail -8
```
Expected: PASS. Failures in `dao13d_test.go`/`fuzhuo_contract_test.go` should be DB-level only — if they call deleted helpers, adapt the call sites per the same patterns above.

- [ ] **Step 7: Commit**

```bash
git add controller/internal/action/ controller/main.go
git commit -m "feat(action): execute flowspec/RTBH via embedded speaker; delete vtysh path"
```

---

### Task 7: API layer — instance/peer endpoints, connector CRUD, flowspec views

**Files:**
- Create: `controller/internal/api/bgp_instance.go`
- Modify: `controller/internal/api/bgp_connector.go`, `controller/internal/api/flowspec.go`, `controller/internal/api/router.go`
- Delete: `controller/internal/api/dao12b_bgp_http_test.go`
- Modify: `controller/internal/api/bgp_connector_vendor_test.go` (rewrite), `controller/internal/api/dao11j_orphan_lock_test.go`, `controller/internal/api/dao14e1_api_test.go`

- [ ] **Step 1: Instance + peer-state endpoints**

`controller/internal/api/bgp_instance.go`:
```go
package api

import (
	"net"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
)

func getBGPInstance(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		inst, err := deps.Store.BGPInstances().Get(c)
		if err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		if inst == nil {
			ok(c, gin.H{"configured": false})
			return
		}
		ok(c, gin.H{"configured": true, "instance": inst, "speaker_running": bgp.Shared() != nil})
	}
}

func updateBGPInstance(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			LocalASN    *int64  `json:"local_asn"`
			RouterID    *string `json:"router_id"`
			ListenPort  *int64  `json:"listen_port"`
			RTBHNextHop *string `json:"rtbh_next_hop"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		inst, err := deps.Store.BGPInstances().Get(c)
		if err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		if inst == nil {
			inst = &store0() // placeholder replaced below
		}
		_ = inst
		_ = strconv.Itoa
		_ = net.ParseIP
		ok(c, gin.H{"ok": true})
	}
}
```
Replace the sketchy tail of `updateBGPInstance` with the real body:
```go
func updateBGPInstance(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			LocalASN    *int64  `json:"local_asn"`
			RouterID    *string `json:"router_id"`
			ListenPort  *int64  `json:"listen_port"`
			RTBHNextHop *string `json:"rtbh_next_hop"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		inst, err := deps.Store.BGPInstances().Get(c)
		if err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		if inst == nil {
			inst = &store.BGPInstance{ListenPort: 179}
		}
		if req.LocalASN != nil {
			if *req.LocalASN < 1 || *req.LocalASN > 4294967295 {
				errResponse(c, http.StatusBadRequest, "local_asn must be between 1 and 4294967295")
				return
			}
			inst.LocalASN = int(*req.LocalASN)
		}
		if req.RouterID != nil {
			if net.ParseIP(strings.TrimSpace(*req.RouterID)) == nil {
				errResponse(c, http.StatusBadRequest, "router_id must be an IPv4 address")
				return
			}
			inst.RouterID = strings.TrimSpace(*req.RouterID)
		}
		if req.ListenPort != nil {
			if *req.ListenPort < 0 || *req.ListenPort > 65535 {
				errResponse(c, http.StatusBadRequest, "listen_port must be 0-65535 (0 disables inbound)")
				return
			}
			inst.ListenPort = int(*req.ListenPort)
		}
		if req.RTBHNextHop != nil {
			v := strings.TrimSpace(*req.RTBHNextHop)
			if v != "" && net.ParseIP(v) == nil {
				errResponse(c, http.StatusBadRequest, "rtbh_next_hop must be an IP address")
				return
			}
			inst.RTBHNextHop = v
		}
		if inst.LocalASN <= 0 || inst.RouterID == "" {
			errResponse(c, http.StatusBadRequest, "local_asn and router_id are required")
			return
		}
		if err := deps.Store.BGPInstances().Upsert(c, inst); err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		publishAfterChange(c, deps, "bgp_instance", "1", "update",
			jsonOrNil(map[string]any{"local_asn": inst.LocalASN, "router_id": inst.RouterID}))
		ok(c, gin.H{"ok": true, "restart_required": bgp.Shared() != nil,
			"note": "instance identity changes take effect after controller restart"})
	}
}

// listBGPPeers returns live session state for the connectors page.
func listBGPPeers(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		sp := bgp.Shared()
		if sp == nil {
			ok(c, gin.H{"peers": []gin.H{}, "speaker_running": false})
			return
		}
		states := sp.PeerStates(c)
		views := make([]gin.H, 0, len(states))
		for _, st := range states {
			views = append(views, gin.H{
				"connector_id": st.ConnectorID, "name": st.Name,
				"neighbor_ip": st.NeighborIP, "session_up": st.SessionUp,
			})
		}
		ok(c, gin.H{"peers": views, "speaker_running": true})
	}
}
```
Imports for the final file: `net`, `net/http`, `strings`, `github.com/gin-gonic/gin`, `internal/bgp`, `internal/store`. (`strconv` not needed — drop it.)

- [ ] **Step 2: Rewrite connector CRUD**

In `controller/internal/api/bgp_connector.go`:
1. Delete: `runVtyshHTTP`, `vtyshHTTPTimeout`, `vtyshHTTPWaitDelay`, `errVtyshHTTPTimeout`, `executableBGPConnector`, `listBGPRoutes`, `testBGPConnector` (all vtysh-based).
2. `createBGPConnector` request struct becomes:
```go
		var req struct {
			Name          string `json:"name" binding:"required"`
			BGPASN        *int64 `json:"bgp_asn"`
			AddressFamily string `json:"address_family"`
			Enabled       *bool  `json:"enabled"`
			Description   string `json:"description"`
			Vendor        string `json:"vendor"`
			Flowspec      *bool  `json:"flowspec_enabled"`
			NeighborIP    string `json:"neighbor_ip"`
			NeighborASN   *int64 `json:"neighbor_asn"`
			MD5Password   string `json:"md5_password"`
		}
```
Validation replaces the vendor block:
```go
		neighborASN := 0
		if req.NeighborASN != nil {
			if *req.NeighborASN < 1 || *req.NeighborASN > 4294967295 {
				errResponse(c, http.StatusBadRequest, "neighbor_asn must be between 1 and 4294967295")
				return
			}
			neighborASN = int(*req.NeighborASN)
		}
		if req.AddressFamily == "" {
			req.AddressFamily = "auto"
		}
		if req.AddressFamily != "auto" && req.AddressFamily != "ipv4" && req.AddressFamily != "ipv6" {
			errResponse(c, http.StatusBadRequest, `address_family must be "auto", "ipv4" or "ipv6"`)
			return
		}
		neighborIP := strings.TrimSpace(req.NeighborIP)
		if enabled && (neighborIP == "" || neighborASN == 0) {
			errResponse(c, http.StatusBadRequest,
				"an enabled connector needs neighbor_ip and neighbor_asn (BGP peering details)")
			return
		}
		if neighborIP != "" && net.ParseIP(neighborIP) == nil {
			errResponse(c, http.StatusBadRequest, "neighbor_ip must be an IP address")
			return
		}
```
`conn := &store.BGPConnector{...}` gains `NeighborIP: neighborIP, NeighborASN: neighborASN, MD5Password: req.MD5Password` and drops `VtyshPath`. After a successful `Create`, sync the speaker:
```go
		if err := syncBGPSpeakerPeers(c, deps); err != nil {
			log.Printf("api: bgp peer sync after connector create: %v", err)
		}
```
3. `updateBGPConnector`: same fields (pointers), same validation against the merged `conn`, plus `syncBGPSpeakerPeers` after `Update`, and after `Delete` in `deleteBGPConnector`.
4. Add the sync helper (top of file):
```go
// syncBGPSpeakerPeers pushes current enabled connectors with peering details
// into the embedded speaker. Best-effort: DB state is authoritative; the
// next CRUD operation retries.
func syncBGPSpeakerPeers(c *gin.Context, deps Dependencies) error {
	sp := bgp.Shared()
	if sp == nil {
		return nil
	}
	conns, err := deps.Store.BGPConnectors().List(c)
	if err != nil {
		return err
	}
	peers := make([]bgp.Peer, 0, len(conns))
	for _, conn := range conns {
		if !conn.Enabled || conn.NeighborIP == "" || conn.NeighborASN == 0 {
			continue
		}
		peers = append(peers, bgp.Peer{
			ConnectorID: conn.ID, Name: conn.Name,
			NeighborIP: conn.NeighborIP, NeighborASN: uint32(conn.NeighborASN),
			MD5Password: conn.MD5Password, AddressFamily: conn.AddressFamily,
		})
	}
	return sp.SyncPeers(c, peers)
}
```
Imports: add `log`, `net`, `internal/bgp`; drop `os/exec`, `sync`, `internal/action/flowspec` (keep `store`).
5. Replace the `test` route handler with a speaker-backed probe:
```go
// testBGPConnector reports the live session state of this connector's peer.
func testBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		sp := bgp.Shared()
		if sp == nil {
			errResponse(c, http.StatusConflict, "bgp speaker not configured (Settings → BGP Instance)")
			return
		}
		for _, st := range sp.PeerStates(c) {
			if st.ConnectorID == conn.ID {
				if st.SessionUp {
					ok(c, gin.H{"ok": true, "output": "session established with " + st.NeighborIP})
				} else {
					ok(c, gin.H{"ok": false, "error": "session down with " + st.NeighborIP})
				}
				return
			}
		}
		errResponse(c, http.StatusConflict, "connector has no peering details configured")
	}
}
```
6. `deleteBGPConnector`'s "announcements in FRR-relevant states" error message: change to "…in flight" (wording only).

- [ ] **Step 3: Rewrite flowspec API**

In `controller/internal/api/flowspec.go`:
1. Delete `normalizeVendor`, `supportedVendors`, `vendorIsExecutable`; the `flowspecView` fields `Vendor`, `Executable`, `Commands`, `WithdrawCommands` are replaced by `Match string`:
```go
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
```
2. `buildFlowspecView` drops vendor/commands logic:
```go
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
```
3. `listFlowspecAnnouncements` response drops `"vendors"`:
```go
		ok(c, gin.H{"announcements": views})
```
4. `previewFlowspecRule`: drop the `Vendor` field and normalizeVendor call; response:
```go
		if err := rule.Validate(); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		ok(c, gin.H{"rule": rule, "match": flowspec.Describe(rule)})
```
5. `forceWithdrawFlowspec`: drop vendor/render/vtysh; the execution tail becomes:
```go
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
```
Imports: drop `context`, `strings`, `internal/action/flowspec` stays; add `internal/bgp`.

- [ ] **Step 4: Routes**

In `controller/internal/api/router.go`, next to the other `settings` BGP routes (~line 227), add:
```go
			settings.GET("/bgp-instance", getBGPInstance(deps))
			settings.PUT("/bgp-instance", updateBGPInstance(deps))
			api.GET("/bgp/peers", listBGPPeers(deps))
```
(The old `settings.GET("/bgp-connectors/:id/routes", listBGPRoutes(deps))` route is deleted with its handler.)

- [ ] **Step 5: Test rewrites**

1. `git rm controller/internal/api/dao12b_bgp_http_test.go` (tests `runVtyshHTTP`).
2. Rewrite `bgp_connector_vendor_test.go` → `bgp_connector_peer_test.go`:
```go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Enabled connectors must carry peering details — an enabled row without
// neighbor_ip/neighbor_asn would fail closed at announce time.
func TestBgpConnectorPeerValidation(t *testing.T) {
	setup, _ := newTestAPI(t) // reuse the existing harness used by bgp_connector tests
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"enabled_without_neighbor_rejected", `{"name":"n1","bgp_asn":65000,"enabled":true}`, http.StatusBadRequest},
		{"enabled_with_neighbor_ok", `{"name":"n2","bgp_asn":65000,"enabled":true,"neighbor_ip":"192.0.2.1","neighbor_asn":65001}`, http.StatusCreated},
		{"disabled_without_neighbor_ok", `{"name":"n3","bgp_asn":65000,"enabled":false}`, http.StatusCreated},
		{"bad_neighbor_ip_rejected", `{"name":"n4","bgp_asn":65000,"enabled":true,"neighbor_ip":"999.1.1.1","neighbor_asn":65001}`, http.StatusBadRequest},
		{"zero_neighbor_asn_rejected", `{"name":"n5","bgp_asn":65000,"enabled":true,"neighbor_ip":"192.0.2.1","neighbor_asn":0}`, http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/bgp-connectors", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		setup.router.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
}
```
Adapt the harness bootstrap (`newTestAPI`) to the one used by the existing connector tests in this package — open `bgp_connector_vendor_test.go` first and mirror its setup lines exactly, only changing the route body cases.
3. `dao11j_orphan_lock_test.go`: replace the vtysh script fixture (lines ~114+) with `bgp.SetShared(&bgp.FakeSpeaker{})` (cleanup: `bgp.SetShared(nil)`); the "barrier before vtysh" assertion becomes "barrier before the fake speaker's withdraw call" (assert `Calls` recorded only after the lock gate).
4. `dao14e1_api_test.go`: swap `vtysh_path` JSON/struct references for `neighbor_ip` (`{"name":"n1","bgp_asn":65000,"neighbor_ip":"192.0.2.1","neighbor_asn":65001,...}`) and `s.bgps.rows[0].NeighborIP` assertions.
5. Run:
```bash
cd controller && GOTOOLCHAIN=auto go build ./... && GOTOOLCHAIN=auto go test ./internal/api/ 2>&1 | tail -6
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add controller/internal/api/ controller/main.go
git commit -m "feat(api): bgp instance/peer endpoints, neighbor CRUD, speaker-backed flowspec views"
```

---

### Task 8: Console

**Files:**
- Modify: `controller/console/src/views/connectors/data.ts`, `controller/console/src/views/connectors/ConnectorDrawer.vue`
- Modify: `controller/console/src/views/mitigations/Flowspec.vue`
- Modify: `controller/console/src/i18n/en.ts`, `controller/console/src/i18n/ar.ts`
- Modify: `controller/console/mock/data.ts`

- [ ] **Step 1: Connector types + form**

In `controller/console/src/views/connectors/data.ts`:
1. `BGPRow`:
```ts
export interface BGPRow extends CommonRow {
  bgp_asn: number
  description: string
  address_family: string
  vendor: string
  flowspec_enabled: boolean
  neighbor_ip: string
  neighbor_asn: number
  md5_password?: string
}
```
2. `Form`: replace `vtysh_path: string` with `neighbor_ip: string; neighbor_asn: number; md5_password: string`.
3. `fillForm` bgp branch:
```ts
    form.bgp_asn = bgp.bgp_asn
    form.neighbor_ip = bgp.neighbor_ip || ''
    form.neighbor_asn = bgp.neighbor_asn || 0
    form.md5_password = ''
    form.description = bgp.description
    form.vendor = bgp.vendor || ''
    form.flowspec_enabled = bgp.flowspec_enabled === true
```
and the default `Form` literal: `bgp_asn: 65000, neighbor_ip: '', neighbor_asn: 0, md5_password: ''` (drop `vtysh_path`).
4. `connectorCheck` bgp cases:
```ts
  if (kind === 'bgp' && form.enabled && (!form.neighbor_ip.trim() || !form.neighbor_asn)) {
    return error('neighborRequired')
  }
```
(drop the `vtyshRequired` and `vendorNeedsFlowspec` checks).
5. `connectorBody` bgp branch:
```ts
  if (kind === 'bgp') return {
    name, bgp_asn: form.bgp_asn, description: form.description, vendor: form.vendor,
    flowspec_enabled: form.flowspec_enabled, address_family: 'auto',
    neighbor_ip: form.neighbor_ip.trim(), neighbor_asn: form.neighbor_asn || undefined,
    ...(form.md5_password.trim() ? { md5_password: form.md5_password.trim() } : {}),
    enabled: form.enabled,
  }
```
6. `testResult` bgp branch keys stay (`connectionOk`/`bgpTestFailed`).

- [ ] **Step 2: ConnectorDrawer form fields**

In `controller/console/src/views/connectors/ConnectorDrawer.vue`, replace the vendor select + vtysh input block (template lines ~85–95) with:
```html
        <label class="field"><span>{{ t('connectors.neighborIp') }} <XTip :text="t('connectors.neighborIpTip')" /></span>
          <input v-model="form.neighbor_ip" class="mono" autocomplete="off" :disabled="disabled"
            placeholder="192.0.2.1"></label>
        <div class="field"><span>{{ t('connectors.neighborAsn') }}</span>
          <XNumber v-model="form.neighbor_asn" :label="t('connectors.neighborAsn')" :min="1" :max="4294967295"
            :disabled="disabled" /></div>
        <label class="field"><span>{{ t('connectors.md5') }} <XTip :text="t('connectors.md5Tip')" /></span>
          <input v-model="form.md5_password" type="password" autocomplete="new-password" :disabled="disabled"></label>
```
Script changes: remove `vendors, vendorName` imports and `vendorOptions`; keep the flowspec switch.

- [ ] **Step 3: Flowspec.vue**

In `controller/console/src/views/mitigations/Flowspec.vue`:
1. Interfaces: `Announcement` drops `vendor`/`executable`/`commands`/`withdraw_commands`, gains `match?: string`; `VendorInfo`/`AnnouncementsResp.vendors` deleted; `PreviewReq` drops `vendor`; `PreviewResp` becomes `{ rule: Rule; match: string }`.
2. State: delete `previewVendor`, `vendors`; `fetchAnnouncements` drops the `vendors.value` assignment.
3. `runPreview` body drops `vendor: previewVendor.value`.
4. Table: delete the vendor `<th>`/`<td>` pair (lines ~197, ~208).
5. Preview form: delete the vendor field div (lines ~225–228); preview result becomes:
```html
        <div v-if="previewResult" class="preview-result">
          <h3>{{ t('flowspec.preview.result') }}</h3>
          <p class="mono">{{ previewResult.match }}</p>
          <pre class="mono">{{ JSON.stringify(previewResult.rule, null, 2) }}</pre>
          <XCopy :text="JSON.stringify(previewResult.rule, null, 2)" />
        </div>
```
6. Drawer: delete the vendor `<dt>/<dd>` (line ~258); replace the two command blocks (lines ~262–267) with:
```html
        <div class="subh">{{ t('flowspec.detail.match') }}</div>
        <pre class="mono cmd">{{ detail.match || detail.rule_name }}</pre>
        <div class="subh">{{ t('flowspec.detail.ruleJson') }}</div>
        <pre class="mono cmd">{{ JSON.stringify(detail.rule, null, 2) }}</pre>
        <XCopy :text="JSON.stringify(detail.rule, null, 2)" />
```
7. `executeWithdraw` response type: `{ ok: true; announcement_id: number; warning?: string; already_withdrawn?: boolean }`.

- [ ] **Step 4: i18n**

In `controller/console/src/i18n/en.ts` connectors section (~line 870): delete `vendor`, `vendorTip`, `exportOnlyTip`, `vtysh`, `vtyshRequired`, `vendorNeedsFlowspec`; change `routesSource` to `'From the embedded GoBGP speaker RIB'`; add:
```ts
  neighborIp: 'Neighbor IP',
  neighborIpTip: 'BGP neighbor (upstream router) this connector peers with',
  neighborAsn: 'Neighbor ASN',
  md5: 'MD5 password (optional)',
  md5Tip: 'TCP MD5 auth shared with the neighbor; leave empty for none',
  neighborRequired: 'An enabled connector needs a neighbor IP and ASN',
```
In the flowspec section add `match: 'Match', ruleJson: 'Rule (JSON)'` and delete export-only strings if referenced. Mirror every key in `ar.ts` with Arabic translations (project convention — every en key has an ar twin).

- [ ] **Step 5: Mock fixtures**

In `controller/console/mock/data.ts`, update bgp connector fixtures to the new shape (`neighbor_ip: '192.0.2.1', neighbor_asn: 65001, neighbor ASN fields; drop vtysh_path/vendor executable semantics`) and flowspec announcement fixtures to carry `match: 'destination 198.51.100.7/32, drop (traffic-rate 0)'` instead of `commands`.

- [ ] **Step 6: Verify**

```bash
cd controller/console && npm run build && npm test 2>&1 | tail -8
```
Expected: type-check + vitest pass. Fix any test fixtures in `console/tests/` that assert vendor/commands fields per the same shape changes.

- [ ] **Step 7: Commit**

```bash
git add controller/console/
git commit -m "feat(console): neighbor peering form + speaker-native flowspec views"
```

---

### Task 9: Deployment

**Files:**
- Modify: `Dockerfile` (lines ~33–36), `docker-compose.yml`, `controller/config.example.yaml`

- [ ] **Step 1: Dockerfile**

Remove `frr` from the apt line and the frr group membership:
```dockerfile
 && apt-get install -y --no-install-recommends ca-certificates curl \
```
Delete the `usermod -aG frr,frrvty xsight \` line.

- [ ] **Step 2: docker-compose.yml**

In the `controller` service: delete `- /run/frr:/run/frr`; add after `ports:` entries:
```yaml
      - "179:179"        # BGP — embedded speaker listener (cap NET_BIND_SERVICE below)
```
and add:
```yaml
    cap_add:
      - NET_BIND_SERVICE
```
with a comment: active-connect-only deployments (peers never dial us) can drop the port mapping and the capability, and set `listen_port: 0` in the BGP instance.

- [ ] **Step 3: config.example.yaml**

Replace the BGP comment block (search `# BGP Flowspec / RTBH`) with:
```yaml
# BGP (embedded GoBGP speaker) — instance identity is configured in the Web
# Console (Settings → BGP Instance): local_asn, router_id, listen_port,
# rtbh_next_hop. Neighbors are configured per connector (Settings → BGP
# Connectors): neighbor_ip, neighbor_asn, md5_password. Nothing BGP-related
# lives in this YAML anymore.
# See docs/FLOWSPEC.md (EN) / docs/FLOWSPEC.ar.md (AR).
```

- [ ] **Step 4: Commit**

```bash
git add Dockerfile docker-compose.yml controller/config.example.yaml
git commit -m "chore(deploy): drop frr; expose BGP 179 with NET_BIND_SERVICE"
```

---

### Task 10: Docs, CHANGELOG, full verification

**Files:**
- Modify: `docs/FLOWSPEC.md`, `docs/FLOWSPEC.ar.md`, `docs/ENTERPRISE-UPGRADE-AR.md`, `CHANGELOG.md`, `CHANGELOG.zh.md`

- [ ] **Step 1: Rewrite docs/FLOWSPEC.md**

Content plan (full rewrite, keep AR twin in sync section-by-section):
- Overview: controller embeds GoBGP; rules originate over BGP (RFC 8955 flowspec, RFC 7999 blackhole RTBH); no local FRR.
- Setup: Settings → BGP Instance (local_asn, router_id, listen_port 179, rtbh_next_hop); Settings → BGP Connectors per upstream router (neighbor_ip, neighbor_asn, md5, address_family, flowspec_enabled).
- Flow: attack → refcounted announcement → speaker AddPath → advertised to all established peers; withdraw on expiry incl. delayed timers; connector disable = session teardown = neighbor auto-withdraw.
- Console: Flowspec tab shows rule JSON + match tuple; force-withdraw; preview shows the match tuple.
- Metrics: `xsight_bgp_peer_up`, `xsight_bgp_paths`, `xsight_bgp_speaker_errors_total` (vtysh metrics removed).
- Limitations: all peers receive all rules (same as the old FRR propagation model); per-peer export filtering is a fast-follow.

- [ ] **Step 2: Update docs/ENTERPRISE-UPGRADE-AR.md**

Replace the §"مُولّد أوامر BGP Flowspec" section (around lines 36, 222–248): the connector type is now the embedded speaker (`bgp_instance` + neighbor fields); drop vtysh/`kind` CLI wording where it describes execution (the `bgp_announcements` kind/rule_spec storage model stays).

- [ ] **Step 3: CHANGELOG entries**

Prepend to `CHANGELOG.md` (and translate for `CHANGELOG.zh.md`), matching the existing style:
```markdown
- BGP speaker: the controller now embeds GoBGP and originates Flowspec (RFC 8955) and RTBH (RFC 7999 blackhole) over real BGP sessions. Connectors are neighbor definitions (neighbor_ip/neighbor_asn/md5) under a new Settings → BGP Instance (local ASN, router-id). The local-FRR/vtysh path and multi-vendor CLI export are removed — [docs/FLOWSPEC.md](docs/FLOWSPEC.md) (AR: [docs/FLOWSPEC.ar.md](docs/FLOWSPEC.ar.md)).
```

- [ ] **Step 4: Full verification**

```bash
cd controller && GOTOOLCHAIN=auto go build ./... && GOTOOLCHAIN=auto go vet ./... && GOTOOLCHAIN=auto go test ./... 2>&1 | tail -12
cd console && npm run build && npm test 2>&1 | tail -6
```
Expected: everything PASS. Run the integration test explicitly once:
```bash
cd controller && GOTOOLCHAIN=auto go test ./internal/bgp/ -run TestIntegration -v 2>&1 | tail -4
```
Also `GOTOOLCHAIN=auto go run . -config config.yaml -migrate` against a scratch postgres if available, else confirm migration SQL by inspection (`CREATE TABLE IF NOT EXISTS bgp_instance…` + three connector ALTERs).

- [ ] **Step 5: Commit**

```bash
git add docs/ CHANGELOG.md CHANGELOG.zh.md
git commit -m "docs: GoBGP speaker model for flowspec/RTBH; changelog"
```

---

## Verification matrix (end state)

| Old | New |
|---|---|
| `runVtysh`/`vtyshTokens`/`isFRRRouteAbsentError` | deleted; speaker calls are typed + idempotent |
| `flowspec.Render` vendor CLI | `flowspec.Describe` match tuple (display only) |
| export-only vendors | deleted — all connectors are BGP neighbors |
| `xsight_vtysh_ops_total` | `xsight_bgp_speaker_errors_total` + `xsight_bgp_peer_up` + `xsight_bgp_paths` |
| FRR in image, `/run/frr` mount | removed; BGP 179 + NET_BIND_SERVICE |
| `RecoverBGPRoutes` re-runs vtysh | re-encodes from DB and re-adds paths in speaker |

## Self-review notes

- Spec coverage: peering model (Tasks 3,5,7), flowspec+RTBH via speaker (2,4,6), vendor removal (2,6,7,8), recovery (6), metrics (3), console (8), deploy (9), docs (10) — all mapped.
- Type consistency: `Speaker`/`Peer`/`PeerState`/`Config` names identical across Tasks 1,3,6,7; `FakeSpeaker` used by Tasks 6,7 tests; `flowspec.Describe` introduced in Task 6 and consumed in Task 7.
- Known risk, handled in-task: gobgp API field-name drift — fix against module source only (Task 3 step 3, Task 4 step 2 list the two likely knobs: `Transport.RemotePort`, `EbgpMultihop`).
