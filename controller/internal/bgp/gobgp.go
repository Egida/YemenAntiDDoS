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
// Pointers keep vet's lock-copy check happy (protobuf messages embed mutexes).
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
	families := map[string]*api.Family{
		"rtbh":     {Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		"flowspec": {Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
	}
	// IPv6 counts fold into the same kinds via a second pass.
	families["rtbh6"] = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
	families["flowspec6"] = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}

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
