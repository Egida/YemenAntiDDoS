package bgp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
)

const speakerTimeout = 30 * time.Second

// noiseFilterLogger wraps gobgp's default logger to drop the noisy
// "cannot set TTL (255) for TCPListener ... operation not supported"
// warnings that GoBGP emits in containers lacking the socket capability.
// The speaker continues to operate normally; only the warning is dropped.
type noiseFilterLogger struct{ log.DefaultLogger }

func (l *noiseFilterLogger) Warn(msg string, fields log.Fields) {
	if strings.Contains(msg, "cannot set TTL") && strings.Contains(msg, "TCPListener") {
		return
	}
	l.DefaultLogger.Warn(msg, fields)
}

// GobgpSpeaker runs an embedded gobgp.Server. Paths live in memory; recovery
// re-adds them from bgp_announcements after a restart (see action.RecoverBGPRoutes).
type GobgpSpeaker struct {
	cfg Config

	mu        sync.Mutex
	peersMu   sync.RWMutex
	srv       *server.BgpServer
	uuids     map[string][]byte // pathKey -> AddPath uuid
	peers     map[int]Peer      // connectorID -> last synced peer
	peerGauge map[string]bool   // BGPPeerUp label pairs ("conn|neighbor") currently exported
	stop      sync.Once
	stopCh    chan struct{}
}

var _ Speaker = (*GobgpSpeaker)(nil)

func NewGobgp(cfg Config) *GobgpSpeaker {
	return &GobgpSpeaker{
		cfg:       cfg,
		uuids:     map[string][]byte{},
		peers:     map[int]Peer{},
		peerGauge: map[string]bool{},
		stopCh:    make(chan struct{}),
	}
}

// server returns the live BGP server (nil until Start succeeds). Every read
// goes through here so the poll goroutine never races Start/Stop writes.
func (s *GobgpSpeaker) server() *server.BgpServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv
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

// Start brings up the embedded speaker. ctx is accepted for interface
// compliance and not used: lifecycle calls run synchronously under the
// internal speaker timeout instead.
func (s *GobgpSpeaker) Start(_ context.Context) error {
	if _, err := s.cfg.NextHop(); err != nil {
		return err
	}
	// Reset lifecycle state so Start-after-Stop works: a consumed sync.Once
	// and a closed stopCh would otherwise break the next start/stop cycle.
	s.mu.Lock()
	s.stopCh = make(chan struct{})
	s.stop = sync.Once{}
	s.uuids = map[string][]byte{}
	s.peerGauge = map[string]bool{}
	s.mu.Unlock()
	s.peersMu.Lock()
	s.peers = map[int]Peer{}
	s.peersMu.Unlock()
	srv := server.NewBgpServer(server.LoggerOption(&noiseFilterLogger{DefaultLogger: *log.NewDefaultLogger()}))
	go srv.Serve()
	ctx, cancel := context.WithTimeout(context.Background(), speakerTimeout)
	defer cancel()
	global := &api.Global{
		Asn:      s.cfg.LocalASN,
		RouterId: s.cfg.RouterID,
	}
	if s.cfg.ListenPort > 0 {
		global.ListenPort = s.cfg.ListenPort
		global.ListenAddresses = []string{"0.0.0.0", "::"}
	} else {
		// gobgp rewrites port 0 to 179 AND an empty address list to
		// 0.0.0.0/:: (oc.SetDefaultGlobalConfigValues), then binds every
		// address — port 0 cannot express "no listener". A negative port
		// survives the defaulting and fails the > 0 listener check, keeping
		// the speaker outbound-only per the Config contract.
		global.ListenPort = -1
	}
	if err := srv.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
		return fmt.Errorf("bgp: start speaker: %w", err)
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()
	go s.pollLoop()
	return nil
}

// Stop shuts the speaker down. ctx is accepted for interface compliance and
// not used (see Start).
func (s *GobgpSpeaker) Stop(_ context.Context) error {
	s.stop.Do(func() { close(s.stopCh) })
	srv := s.server()
	if srv != nil {
		srv.Stop()
	}
	return nil
}

// peerFamilies returns the unicast + flowspec families for the peer's AF,
// as pointers because that is the generated API element type.
func peerFamilies(af string) []*api.Family {
	if af == "ipv6" {
		return []*api.Family{
			{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST},
			{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
		}
	}
	return []*api.Family{
		{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
	}
}

// effectiveAF resolves "auto" by parsing the neighbor address; an IPv4-mapped
// IPv6 literal (::ffff:a.b.c.d) counts as IPv4.
func effectiveAF(p Peer) string {
	if p.AddressFamily == "auto" {
		if ip := net.ParseIP(p.NeighborIP); ip != nil && ip.To4() == nil {
			return "ipv6"
		}
		return "ipv4"
	}
	return p.AddressFamily
}

// normalizeAddr canonicalizes a neighbor address so "2001:DB8::1" and
// "2001:db8::1" cannot be treated as two different peers and flap sessions.
func normalizeAddr(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
		return ip.String()
	}
	return s
}

func (s *GobgpSpeaker) addPeer(ctx context.Context, p Peer) error {
	if p.RemotePort > 65535 {
		return fmt.Errorf("bgp: peer %s: remote port %d exceeds 65535", p.NeighborIP, p.RemotePort)
	}
	afs := make([]*api.AfiSafi, 0, 2)
	for _, f := range peerFamilies(effectiveAF(p)) {
		afs = append(afs, &api.AfiSafi{Config: &api.AfiSafiConfig{
			Family: &api.Family{Afi: f.Afi, Safi: f.Safi}, Enabled: true,
		}})
	}
	// The speaker is outbound-only: RemotePort dials a neighbor listening on
	// a custom port instead of TCP/179 (tests, custom deployments).
	var transport *api.Transport
	if p.RemotePort != 0 {
		transport = &api.Transport{RemotePort: p.RemotePort}
	}
	err := s.server().AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.NeighborIP,
			PeerAsn:         p.NeighborASN,
			AuthPassword:    p.MD5Password,
			Description:     p.Name,
		},
		AfiSafis:  afs,
		Transport: transport,
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
		desired[normalizeAddr(p.NeighborIP)] = p
	}
	existing := map[string]bool{}
	if err := s.server().ListPeer(cctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		existing[normalizeAddr(p.Conf.GetNeighborAddress())] = true
	}); err != nil {
		metrics.BGPSpeakerErrors.Inc()
		return fmt.Errorf("bgp: list peers: %w", err)
	}
	// Duplicate ConnectorIDs, or the same neighbor listed under two
	// connectors, collapse last-writer-wins for console attribution only;
	// the session config sent to gobgp remains correct.
	for addr, p := range desired {
		s.peersMu.RLock()
		old, ok := s.peers[p.ConnectorID]
		s.peersMu.RUnlock()
		if ok && existing[addr] &&
			old.NeighborASN == p.NeighborASN && old.MD5Password == p.MD5Password &&
			old.AddressFamily == p.AddressFamily && old.RemotePort == p.RemotePort {
			continue
		}
		if existing[addr] {
			if err := s.server().DeletePeer(cctx, &api.DeletePeerRequest{Address: addr}); err != nil {
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
			if err := s.server().DeletePeer(cctx, &api.DeletePeerRequest{Address: addr}); err != nil {
				metrics.BGPSpeakerErrors.Inc()
				return fmt.Errorf("bgp: delete peer %s: %w", addr, err)
			}
		}
	}
	s.peersMu.Lock()
	s.peers = map[int]Peer{}
	for _, p := range desired {
		s.peers[p.ConnectorID] = p
	}
	s.peersMu.Unlock()
	return nil
}

// PeerStates snapshots live session state, joined with connector identity.
func (s *GobgpSpeaker) PeerStates(ctx context.Context) []PeerState {
	cctx, cancel := context.WithTimeout(ctx, speakerTimeout)
	defer cancel()
	s.peersMu.RLock()
	byAddr := map[string]Peer{}
	for _, p := range s.peers {
		byAddr[normalizeAddr(p.NeighborIP)] = p
	}
	s.peersMu.RUnlock()
	out := []PeerState{}
	if err := s.server().ListPeer(cctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		addr := normalizeAddr(p.Conf.GetNeighborAddress())
		st := PeerState{NeighborIP: addr, SessionUp: p.State.GetSessionState() == api.PeerState_ESTABLISHED}
		if peer, ok := byAddr[addr]; ok {
			st.ConnectorID = peer.ConnectorID
			st.Name = peer.Name
		}
		out = append(out, st)
	}); err != nil {
		metrics.BGPSpeakerErrors.Inc()
	}
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

// pollOnce refreshes peer gauges and retires series for peers that went
// away. Path gauges are maintained at mutation time (addPath/deletePath):
// gobgp's ListPath API never populates path UUIDs, so a polled count cannot
// distinguish locally-originated paths from learned ones.
func (s *GobgpSpeaker) pollOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), speakerTimeout)
	defer cancel()
	current := map[string]bool{} // exported label pairs, "conn|neighbor"
	for _, st := range s.PeerStates(ctx) {
		conn := fmt.Sprintf("%d", st.ConnectorID)
		current[conn+"|"+st.NeighborIP] = true
		v := 0.0
		if st.SessionUp {
			v = 1
		}
		metrics.BGPPeerUp.WithLabelValues(conn, st.NeighborIP).Set(v)
	}
	s.mu.Lock()
	known := s.peerGauge
	s.peerGauge = current
	s.mu.Unlock()
	// Retire every pair the previous poll exported that this one doesn't:
	// deleted peers (or peers re-attributed to a different connector) would
	// otherwise keep their last gauge value forever.
	for pair := range known {
		if !current[pair] {
			conn, neighbor, _ := strings.Cut(pair, "|")
			metrics.BGPPeerUp.DeleteLabelValues(conn, neighbor)
		}
	}
}

// pathKind maps a path key to its BGPPaths gauge label.
func pathKind(key string) string {
	if strings.HasPrefix(key, "rtbh") {
		return "rtbh"
	}
	return "flowspec"
}

// announce/withdraw primitives shared by the four public path methods.
func (s *GobgpSpeaker) addPath(ctx context.Context, key string, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface) error {
	apiPath, err := apiutil.NewPath(nlri, false, attrs, time.Now())
	if err != nil {
		return fmt.Errorf("bgp: marshal path: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, speakerTimeout)
	defer cancel()
	resp, err := s.server().AddPath(cctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: apiPath})
	if err != nil {
		metrics.BGPSpeakerErrors.Inc()
		return fmt.Errorf("bgp: add path: %w", err)
	}
	s.mu.Lock()
	s.uuids[key] = resp.Uuid
	s.mu.Unlock()
	metrics.BGPPaths.WithLabelValues(pathKind(key)).Inc()
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
		err = s.server().DeletePath(cctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Uuid: uuid})
	} else {
		// UUID lost (speaker restarted mid-flight): delete by exact NLRI.
		wd, werr := apiutil.NewPath(nlri, true, attrs, time.Now())
		if werr != nil {
			return fmt.Errorf("bgp: marshal withdraw path: %w", werr)
		}
		err = s.server().DeletePath(cctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: wd})
	}
	if err != nil {
		metrics.BGPSpeakerErrors.Inc()
		return fmt.Errorf("bgp: delete path: %w", err)
	}
	metrics.BGPPaths.WithLabelValues(pathKind(key)).Dec()
	return nil
}

// checkNextHopFamily rejects an IPv6 rtbh next-hop for an IPv4 route. The
// inverse (IPv4 next-hop on an IPv6 route) is fine: encodeBlackhole falls
// back to "::" and gobgp rewrites it per-peer as next-hop-self.
func checkNextHopFamily(prefix, nh string) error {
	pfxIP, _, err := parsePrefix(prefix)
	if err != nil {
		return err
	}
	if net.ParseIP(nh).To4() == nil {
		if pfx := net.ParseIP(pfxIP.String()); pfx != nil && pfx.To4() != nil {
			return fmt.Errorf("bgp: rtbh next-hop %q is IPv6 but route %q is IPv4", nh, prefix)
		}
	}
	return nil
}

// encodeBlackholeChecked resolves and validates the RTBH next-hop, then
// encodes the blackhole origination for prefix.
func (s *GobgpSpeaker) encodeBlackholeChecked(prefix string) (key string, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface, err error) {
	nh, err := s.cfg.NextHop()
	if err != nil {
		return "", nil, nil, err
	}
	if err := checkNextHopFamily(prefix, nh); err != nil {
		return "", nil, nil, err
	}
	return encodeBlackhole(prefix, nh)
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
	key, nlri, attrs, err := s.encodeBlackholeChecked(prefix)
	if err != nil {
		return err
	}
	return s.addPath(ctx, key, nlri, attrs)
}

func (s *GobgpSpeaker) WithdrawBlackhole(ctx context.Context, prefix string) error {
	key, nlri, attrs, err := s.encodeBlackholeChecked(prefix)
	if err != nil {
		return err
	}
	return s.deletePath(ctx, key, nlri, attrs)
}
