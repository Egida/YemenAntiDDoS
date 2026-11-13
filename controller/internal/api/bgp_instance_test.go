package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func bgpInstanceRequest(t *testing.T, s *dao11cStore, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/api/settings/bgp-instance", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "dao11c")
	NewRouter(Dependencies{Store: s, APIKey: "dao11c"}).ServeHTTP(w, req)
	return w
}

func TestBGPInstanceEndpoints(t *testing.T) {
	s := dao11cFixture()

	w := bgpInstanceRequest(t, s, http.MethodGet, "")
	if w.Code != http.StatusOK {
		t.Fatalf("initial GET status = %d: %s", w.Code, w.Body.String())
	}
	var view map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if configured, _ := view["configured"].(bool); configured {
		t.Fatalf("initial GET configured = true, want false: %s", w.Body.String())
	}

	w = bgpInstanceRequest(t, s, http.MethodPut, `{"local_asn":65000,"router_id":"192.0.2.1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status = %d: %s", w.Code, w.Body.String())
	}

	w = bgpInstanceRequest(t, s, http.MethodGet, "")
	if w.Code != http.StatusOK {
		t.Fatalf("configured GET status = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if configured, _ := view["configured"].(bool); !configured {
		t.Fatalf("configured GET configured = false, want true: %s", w.Body.String())
	}

	w = bgpInstanceRequest(t, s, http.MethodPut, `{"local_asn":65000,"router_id":"2001:db8::1"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("IPv6 router_id status = %d, want 400: %s", w.Code, w.Body.String())
	}
}
