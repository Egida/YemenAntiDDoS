package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
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
