package bgp

import (
	"context"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"

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

func listDestinations(t *testing.T, sp *GobgpSpeaker, fam *api.Family) map[string]int {
	t.Helper()
	counts := map[string]int{}
	if err := sp.server().ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    fam,
	}, func(d *api.Destination) {
		counts[d.Prefix] = len(d.Paths)
	}); err != nil {
		t.Logf("list path: %v", err)
	}
	return counts
}

func TestIntegrationFlowspecAndBlackholePropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	upstream := startSpeaker(t, 65001, "192.0.2.10", 11790)
	ctrl := startSpeaker(t, 65000, "192.0.2.9", 0)

	ctx, cancel := context.WithTimeout(context.Background(), speakerTimeout)
	defer cancel()
	// gobgp drops inbound connections from neighbors it has no config for
	// (passConnToPeer), so the upstream must also know the ctrl speaker.
	// The dead RemotePort keeps the upstream's active dial away from any
	// daemon a host may run on TCP/179; the ctrl's inbound connection is
	// matched by neighbor address regardless of transport config.
	if err := upstream.SyncPeers(ctx, []Peer{{
		ConnectorID: 99, Name: "ctrl", NeighborIP: "127.0.0.1", NeighborASN: 65000,
		AddressFamily: "ipv4", RemotePort: 11791,
	}}); err != nil {
		t.Fatalf("sync upstream peers: %v", err)
	}
	if err := ctrl.SyncPeers(ctx, []Peer{{
		ConnectorID: 1, Name: "upstream", NeighborIP: "127.0.0.1", NeighborASN: 65001,
		AddressFamily: "ipv4", RemotePort: 11790,
	}}); err != nil {
		t.Fatalf("sync peers: %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
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
		t.Fatalf("session never established; upstream states: %+v ctrl states: %+v",
			upstream.PeerStates(ctx), ctrl.PeerStates(ctx))
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
		for prefix := range listDestinations(t, upstream, fsFam) {
			// Flowspec destinations render as "[destination: ...][protocol: ...]"
			// component strings — match on the contained prefix, not equality.
			if strings.Contains(prefix, "198.51.100.7/32") {
				sawFS = true
			}
		}
		if _, ok := listDestinations(t, upstream, ucFam)["198.51.100.9/32"]; ok {
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
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		goneFS, goneBH := true, true
		for prefix := range listDestinations(t, upstream, fsFam) {
			if strings.Contains(prefix, "198.51.100.7/32") {
				goneFS = false
			}
		}
		if _, ok := listDestinations(t, upstream, ucFam)["198.51.100.9/32"]; ok {
			goneBH = false
		}
		if goneFS && goneBH {
			return // success
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("upstream still holds withdrawn paths")
}
