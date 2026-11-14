package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

func bgpInstanceRequest(t *testing.T, s store.Store, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/api/settings/bgp-instance", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "dao11c")
	NewRouter(Dependencies{Store: s, APIKey: "dao11c"}).ServeHTTP(w, req)
	return w
}

func TestBGPInstanceEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if restart, _ := view["restart_required"].(bool); !restart {
		t.Fatalf("restart_required = false, want true: %s", w.Body.String())
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

	w = bgpInstanceRequest(t, s, http.MethodPut, `{"local_asn":65001}`)
	if w.Code != http.StatusOK {
		t.Fatalf("partial PUT status = %d: %s", w.Code, w.Body.String())
	}
	inst, err := s.BGPInstances().Get(t.Context())
	if err != nil || inst == nil {
		t.Fatalf("get stored instance: %v", err)
	}
	if inst.LocalASN != 65001 || inst.RouterID != "192.0.2.1" {
		t.Fatalf("partial PUT lost fields: %+v", inst)
	}

	w = bgpInstanceRequest(t, s, http.MethodPut, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("empty PUT status = %d: %s", w.Code, w.Body.String())
	}
	inst, err = s.BGPInstances().Get(t.Context())
	if err != nil || inst == nil {
		t.Fatalf("get stored instance after empty PUT: %v", err)
	}
	if inst.LocalASN != 65001 || inst.RouterID != "192.0.2.1" {
		t.Fatalf("empty PUT corrupted instance: %+v", inst)
	}

	w = bgpInstanceRequest(t, s, http.MethodPut, `{"local_asn":65000,"router_id":"2001:db8::1"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("IPv6 router_id status = %d, want 400: %s", w.Code, w.Body.String())
	}
	inst, err = s.BGPInstances().Get(t.Context())
	if err != nil || inst == nil {
		t.Fatalf("get stored instance after invalid PUT: %v", err)
	}
	if inst.LocalASN != 65001 || inst.RouterID != "192.0.2.1" {
		t.Fatalf("invalid PUT persisted changes: %+v", inst)
	}
}

func TestBGPInstanceFakeStoreAlwaysReturnsRepository(t *testing.T) {
	s := &dao11cStore{}
	inst, err := s.BGPInstances().Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if inst != nil {
		t.Fatalf("uninitialized fake instance = %+v, want nil", inst)
	}
}

type bgpInstanceConcurrentRepo struct {
	mu         sync.Mutex
	inst       store.BGPInstance
	gets       int
	firstGet   chan struct{}
	secondGet  chan struct{}
	secondOnce sync.Once
}

func (r *bgpInstanceConcurrentRepo) Get(context.Context) (*store.BGPInstance, error) {
	r.mu.Lock()
	r.gets++
	get := r.gets
	inst := r.inst
	r.mu.Unlock()
	if get == 1 {
		close(r.firstGet)
		select {
		case <-r.secondGet:
		case <-time.After(100 * time.Millisecond):
		}
	} else if get == 2 {
		r.secondOnce.Do(func() { close(r.secondGet) })
	}
	copy := inst
	return &copy, nil
}

func (r *bgpInstanceConcurrentRepo) Upsert(_ context.Context, inst *store.BGPInstance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inst = *inst
	return nil
}

type bgpInstanceConcurrentStore struct {
	*dao11cStore
	instances *bgpInstanceConcurrentRepo
}

func (s *bgpInstanceConcurrentStore) BGPInstances() store.BGPInstanceRepo {
	return s.instances
}

func TestBGPInstanceConcurrentPartialUpdatesPreserveBothFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &bgpInstanceConcurrentRepo{
		inst:      store.BGPInstance{LocalASN: 65000, RouterID: "192.0.2.1", ListenPort: 179},
		firstGet:  make(chan struct{}),
		secondGet: make(chan struct{}),
	}
	s := &bgpInstanceConcurrentStore{dao11cStore: dao11cFixture(), instances: repo}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, body := range []string{`{"local_asn":65001}`, `{"rtbh_next_hop":"192.0.2.254"}`} {
		wg.Add(1)
		go func(body string) {
			defer wg.Done()
			<-start
			w := bgpInstanceRequest(t, s, http.MethodPut, body)
			if w.Code != http.StatusOK {
				t.Errorf("PUT %s status = %d: %s", body, w.Code, w.Body.String())
			}
		}(body)
	}
	close(start)
	wg.Wait()

	inst, err := repo.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if inst.LocalASN != 65001 || inst.RTBHNextHop != "192.0.2.254" {
		t.Fatalf("concurrent partial updates lost a field: %+v", inst)
	}
}
