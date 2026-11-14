package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

func bgpPeerRequest(t *testing.T, method, target, body, id string, h gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h(c)
	return w
}

// Enabled connectors must carry peering details because the embedded speaker
// cannot establish a session from a connector row without them.
func TestBgpConnectorPeerValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"enabled_without_neighbor_rejected", `{"name":"n1","bgp_asn":65000,"enabled":true}`, http.StatusBadRequest},
		{"enabled_with_neighbor_ok", `{"name":"n2","bgp_asn":65000,"enabled":true,"neighbor_ip":"192.0.2.1","neighbor_asn":65001}`, http.StatusCreated},
		{"disabled_without_neighbor_ok", `{"name":"n3","bgp_asn":65000,"enabled":false}`, http.StatusCreated},
		{"bad_neighbor_ip_rejected", `{"name":"n4","bgp_asn":65000,"enabled":true,"neighbor_ip":"999.1.1.1","neighbor_asn":65001}`, http.StatusBadRequest},
		{"zero_neighbor_asn_rejected", `{"name":"n5","bgp_asn":65000,"enabled":true,"neighbor_ip":"192.0.2.1","neighbor_asn":0}`, http.StatusBadRequest},
		{"neighbor_asn_out_of_range_rejected", `{"name":"n6","bgp_asn":65000,"enabled":true,"neighbor_ip":"192.0.2.1","neighbor_asn":4294967296}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao11cFixture()
			w := bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors", tc.body, "",
				createBGPConnector(Dependencies{Store: s}))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestBgpConnectorMergedEnablementRequiresNeighbor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := dao11cFixture()
	s.bgps.rows[0].Enabled = false
	s.bgps.rows[0].NeighborIP = ""
	s.bgps.rows[0].NeighborASN = 0

	w := bgpPeerRequest(t, http.MethodPut, "/api/settings/bgp-connectors/1",
		`{"enabled":true}`, "1", updateBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	conn, err := s.BGPConnectors().Get(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Enabled {
		t.Fatal("rejected merged-state update persisted enabled=true")
	}
}

func TestBgpConnectorTestProbeUsesPeerState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &bgp.FakeSpeaker{States: []bgp.PeerState{{ConnectorID: 1, NeighborIP: "192.0.2.1", SessionUp: true}}}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })

	s := dao11cFixture()
	w := bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors/1/test", "", "1",
		testBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "session established") {
		t.Fatalf("status = %d, want 200 session established: %s", w.Code, w.Body.String())
	}

	w = bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors/999/test", "", "999",
		testBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing connector status = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestBgpConnectorTestProbeDownAndMissingStates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &bgp.FakeSpeaker{States: []bgp.PeerState{{ConnectorID: 1, NeighborIP: "192.0.2.1", SessionUp: false}}}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })

	s := dao11cFixture()
	w := bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors/1/test", "", "1",
		testBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusOK {
		t.Fatalf("down session status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"error":"session down"`) ||
		!strings.Contains(w.Body.String(), `"output":"session down with 192.0.2.1"`) {
		t.Fatalf("down session response shape = %s", w.Body.String())
	}

	fake.States = nil
	w = bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors/1/test", "", "1",
		testBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "peer not present in the running speaker") {
		t.Fatalf("missing peer response = %d %s", w.Code, w.Body.String())
	}

	s.bgps.rows[0].NeighborIP = ""
	s.bgps.rows[0].NeighborASN = 0
	w = bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors/1/test", "", "1",
		testBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no peering details configured") {
		t.Fatalf("missing details response = %d %s", w.Code, w.Body.String())
	}

	s.bgps.rows[0].Enabled = false
	w = bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors/1/test", "", "1",
		testBGPConnector(Dependencies{Store: s}))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "connector is disabled") {
		t.Fatalf("disabled response = %d %s", w.Code, w.Body.String())
	}
}

func TestBgpConnectorCRUDSyncsSpeakerPeers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := &bgp.FakeSpeaker{}
	bgp.SetShared(fake)
	t.Cleanup(func() { bgp.SetShared(nil) })

	s := dao11cFixture()
	deps := Dependencies{Store: s}
	w := bgpPeerRequest(t, http.MethodPost, "/api/settings/bgp-connectors",
		`{"name":"peer","bgp_asn":65000,"enabled":true,"neighbor_ip":"192.0.2.1","neighbor_asn":65001}`, "",
		createBGPConnector(deps))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", w.Code, w.Body.String())
	}

	w = bgpPeerRequest(t, http.MethodPut, "/api/settings/bgp-connectors/2",
		`{"neighbor_ip":"192.0.2.2","neighbor_asn":65002}`, "2", updateBGPConnector(deps))
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", w.Code, w.Body.String())
	}

	w = bgpPeerRequest(t, http.MethodDelete, "/api/settings/bgp-connectors/2", "", "2",
		deleteBGPConnector(deps))
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", w.Code, w.Body.String())
	}

	if got := fake.Count("sync_peers"); got != 3 {
		t.Fatalf("sync_peers calls = %d, want 3", got)
	}
}

type bgpBlockingSyncSpeaker struct {
	mu          sync.Mutex
	peers       []bgp.Peer
	calls       atomic.Int64
	firstSync   chan struct{}
	releaseSync chan struct{}
}

func (s *bgpBlockingSyncSpeaker) Start(context.Context) error { return nil }
func (s *bgpBlockingSyncSpeaker) Stop(context.Context) error  { return nil }
func (s *bgpBlockingSyncSpeaker) AnnounceFlowspec(context.Context, flowspec.Rule) error {
	return nil
}
func (s *bgpBlockingSyncSpeaker) WithdrawFlowspec(context.Context, flowspec.Rule) error {
	return nil
}
func (s *bgpBlockingSyncSpeaker) AnnounceBlackhole(context.Context, string) error { return nil }
func (s *bgpBlockingSyncSpeaker) WithdrawBlackhole(context.Context, string) error { return nil }
func (s *bgpBlockingSyncSpeaker) PeerStates(context.Context) []bgp.PeerState      { return nil }

func (s *bgpBlockingSyncSpeaker) SyncPeers(_ context.Context, peers []bgp.Peer) error {
	call := s.calls.Add(1)
	if call == 1 {
		close(s.firstSync)
		<-s.releaseSync
	}
	s.mu.Lock()
	s.peers = append([]bgp.Peer(nil), peers...)
	s.mu.Unlock()
	return nil
}

func (s *bgpBlockingSyncSpeaker) syncedPeers() []bgp.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bgp.Peer(nil), s.peers...)
}

func TestBgpConnectorConcurrentUpdatesKeepAllEnabledPeers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	speaker := &bgpBlockingSyncSpeaker{firstSync: make(chan struct{}), releaseSync: make(chan struct{})}
	bgp.SetShared(speaker)
	t.Cleanup(func() { bgp.SetShared(nil) })

	s := dao11cFixture()
	s.bgps.rows = []store.BGPConnector{
		{ID: 1, Name: "one", BGPASN: 65000, AddressFamily: "auto", Enabled: true, NeighborIP: "192.0.2.1", NeighborASN: 65001},
		{ID: 2, Name: "two", BGPASN: 65000, AddressFamily: "auto", Enabled: false},
	}
	deps := Dependencies{Store: s}

	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		w := bgpPeerRequest(t, http.MethodPut, "/api/settings/bgp-connectors/1",
			`{"description":"updated"}`, "1", updateBGPConnector(deps))
		if w.Code != http.StatusOK {
			t.Errorf("first update status = %d: %s", w.Code, w.Body.String())
		}
	}()
	<-speaker.firstSync

	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		w := bgpPeerRequest(t, http.MethodPut, "/api/settings/bgp-connectors/2",
			`{"enabled":true,"neighbor_ip":"192.0.2.2","neighbor_asn":65002}`, "2", updateBGPConnector(deps))
		if w.Code != http.StatusOK {
			t.Errorf("second update status = %d: %s", w.Code, w.Body.String())
		}
	}()

	select {
	case <-bDone:
	case <-time.After(100 * time.Millisecond):
	}
	close(speaker.releaseSync)
	<-aDone
	<-bDone

	got := map[int]bool{}
	for _, peer := range speaker.syncedPeers() {
		got[peer.ConnectorID] = true
	}
	if !got[1] || !got[2] {
		t.Fatalf("final speaker peers = %+v, want connectors 1 and 2", got)
	}
}
