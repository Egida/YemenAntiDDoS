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
