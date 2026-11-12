package bgp

import (
	"context"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
)

// Two in-process speakers: the controller speaker peers with a fake upstream.
// The upstream receives the flowspec path (SAFI 133) and the blackhole
// unicast path (SAFI 1) with the right attributes.
func startSpeaker(t *testing.T, asn uint32, routerID string, port int32) *GobgpSpeaker {
	t.Helper()
	cfg := Config{LocalASN: asn, RouterID: routerID, ListenPort: port, RTBHNextHop: routerID}
	sp := NewGobgp(cfg)
	if err := sp.Start(context.Background()); err != nil {
		t.Fatalf("start speaker: %v", err)
	}
	t.Cleanup(func() { _ = sp.Stop(context.Background()) })
	return sp
}

func listDestinations(sp *GobgpSpeaker, fam *api.Family) (map[string][]*api.Path, error) {
	out := map[string][]*api.Path{}
	err := sp.server().ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    fam,
	}, func(d *api.Destination) {
		out[d.Prefix] = d.Paths
	})
	return out, err
}

// pattrs decodes a path's API attributes back into native gobgp types.
func pattrs(t *testing.T, p *api.Path) []bgp.PathAttributeInterface {
	t.Helper()
	raw := p.GetPattrs()
	out := make([]bgp.PathAttributeInterface, 0, len(raw))
	for _, a := range raw {
		decoded, err := apiutil.UnmarshalAttribute(a)
		if err != nil {
			t.Fatalf("unmarshal attr: %v", err)
		}
		out = append(out, decoded)
	}
	return out
}

func assertBlackholeAttrs(t *testing.T, p *api.Path) {
	t.Helper()
	attrs := pattrs(t, p)
	for _, a := range attrs {
		communities, ok := a.(*bgp.PathAttributeCommunities)
		if !ok {
			continue
		}
		for _, c := range communities.Value {
			if c == blackholeCommunity {
				return
			}
		}
	}
	t.Fatalf("blackhole path missing community %d; attrs: %v", blackholeCommunity, attrs)
}

func assertFlowspecAttrs(t *testing.T, p *api.Path) {
	t.Helper()
	attrs := pattrs(t, p)
	for _, a := range attrs {
		ec, ok := a.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if tr, ok := c.(*bgp.TrafficRateExtended); ok && tr.AS == 0 && tr.Rate == 0 {
				return
			}
		}
	}
	t.Fatalf("flowspec path missing traffic-rate drop extended community; attrs: %v", attrs)
}

func peerUp(states []PeerState, connectorID int, neighborIP string) bool {
	for _, st := range states {
		if st.SessionUp && st.ConnectorID == connectorID && st.NeighborIP == neighborIP {
			return true
		}
	}
	return false
}

func TestIntegrationFlowspecAndBlackholePropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	const (
		upstreamConnectorID = 99
		ctrlConnectorID     = 1
	)
	upstream := startSpeaker(t, 65001, "192.0.2.10", 11790)
	ctrl := startSpeaker(t, 65000, "192.0.2.9", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// gobgp drops inbound connections from neighbors it has no config for
	// (passConnToPeer), so the upstream must also know the ctrl speaker.
	// The dead RemotePort keeps the upstream's active dial away from any
	// daemon a host may run on TCP/179; the ctrl's inbound connection is
	// matched by neighbor address regardless of transport config.
	if err := upstream.SyncPeers(ctx, []Peer{{
		ConnectorID: upstreamConnectorID, Name: "ctrl", NeighborIP: "127.0.0.1", NeighborASN: 65000,
		AddressFamily: "ipv4", RemotePort: 11791,
	}}); err != nil {
		t.Fatalf("sync upstream peers: %v", err)
	}
	if err := ctrl.SyncPeers(ctx, []Peer{{
		ConnectorID: ctrlConnectorID, Name: "upstream", NeighborIP: "127.0.0.1", NeighborASN: 65001,
		AddressFamily: "ipv4", RemotePort: 11790,
	}}); err != nil {
		t.Fatalf("sync peers: %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	established := false
	for time.Now().Before(deadline) && !established {
		established = peerUp(upstream.PeerStates(ctx), upstreamConnectorID, "127.0.0.1")
		time.Sleep(200 * time.Millisecond)
	}
	if !established {
		t.Fatalf("session never established; upstream states: %+v ctrl states: %+v",
			upstream.PeerStates(ctx), ctrl.PeerStates(ctx))
	}
	if !peerUp(ctrl.PeerStates(ctx), ctrlConnectorID, "127.0.0.1") {
		t.Fatalf("controller does not see the session up; ctrl states: %+v", ctrl.PeerStates(ctx))
	}

	rule := flowspec.Rule{Name: "xsight-test", Prefix: "198.51.100.7/32", Action: flowspec.ActionDrop}
	if err := ctrl.AnnounceFlowspec(ctx, rule); err != nil {
		t.Fatalf("announce flowspec: %v", err)
	}
	if err := ctrl.AnnounceBlackhole(ctx, "198.51.100.9/32"); err != nil {
		t.Fatalf("announce blackhole: %v", err)
	}

	fsFam := &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}
	ucFam := &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}

	var sawFS, sawBH bool
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !(sawFS && sawBH) {
		fsPaths, err := listDestinations(upstream, fsFam)
		if err != nil {
			t.Fatalf("list flowspec paths: %v", err)
		}
		for prefix, paths := range fsPaths {
			// Flowspec destinations render as "[destination: ...][protocol: ...]"
			// component strings — match on the contained prefix, not equality.
			if !sawFS && strings.Contains(prefix, "198.51.100.7/32") {
				if len(paths) == 0 {
					t.Fatalf("flowspec destination %q has no paths", prefix)
				}
				assertFlowspecAttrs(t, paths[0])
				sawFS = true
			}
		}
		ucPaths, err := listDestinations(upstream, ucFam)
		if err != nil {
			t.Fatalf("list unicast paths: %v", err)
		}
		if paths, ok := ucPaths["198.51.100.9/32"]; ok && !sawBH {
			if len(paths) == 0 {
				t.Fatal("blackhole destination has no paths")
			}
			assertBlackholeAttrs(t, paths[0])
			sawBH = true
		}
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
	withdrawn := false
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !withdrawn {
		fsPaths, err := listDestinations(upstream, fsFam)
		if err != nil {
			t.Fatalf("list flowspec paths: %v", err)
		}
		goneFS := true
		for prefix := range fsPaths {
			if strings.Contains(prefix, "198.51.100.7/32") {
				goneFS = false
			}
		}
		ucPaths, err := listDestinations(upstream, ucFam)
		if err != nil {
			t.Fatalf("list unicast paths: %v", err)
		}
		_, bhPresent := ucPaths["198.51.100.9/32"]
		withdrawn = goneFS && !bhPresent
		if !withdrawn {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if !withdrawn {
		t.Fatal("upstream still holds withdrawn paths")
	}
	// The paths must have left because of the withdraw, not a dropped session.
	if !peerUp(upstream.PeerStates(ctx), upstreamConnectorID, "127.0.0.1") {
		t.Fatal("upstream session dropped during withdrawal")
	}
}

func TestSyncPeersRemotePortChangeBounces(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	sp := startSpeaker(t, 65002, "192.0.2.20", 11793)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	peer := Peer{ConnectorID: 7, Name: "p", NeighborIP: "127.0.0.1", NeighborASN: 65003, AddressFamily: "ipv4", RemotePort: 11794}
	if err := sp.SyncPeers(ctx, []Peer{peer}); err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	assertRemotePort := func(want uint32) {
		t.Helper()
		found := uint32(0)
		if err := sp.server().ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
			if p.Conf.GetNeighborAddress() == "127.0.0.1" {
				found = p.Transport.GetRemotePort()
			}
		}); err != nil {
			t.Fatalf("list peers: %v", err)
		}
		if found != want {
			t.Fatalf("remote port = %d, want %d", found, want)
		}
	}
	assertRemotePort(11794)
	peer.RemotePort = 11795
	if err := sp.SyncPeers(ctx, []Peer{peer}); err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	assertRemotePort(11795)
}
