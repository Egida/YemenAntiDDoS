package tests

// posture_history_api_test.go — TDD coverage for GET /api/nodes/posture/history
// (Task 4 of the inline posture history feature).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestPostureHistoryAPI(t *testing.T) {
	ms := NewMockStore()
	r := setupRouter(ms)

	do := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// Seed two distinct posture points via the repo's BulkInsert.
	now := time.Now().UTC().Truncate(time.Second)
	seed := []store.PosturePoint{
		{Time: now.Add(-2 * time.Minute), NodeID: "edge-1", EmergencyDrops: 42},
		{Time: now.Add(-1 * time.Minute), NodeID: "edge-2", EmergencyDrops: 7},
	}
	if err := ms.NodePosture().BulkInsert(context.Background(), seed); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}

	// 1. Default request → 200, JSON array of 2 objects with the wire keys.
	w := do("/api/nodes/posture/history")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("response not a JSON array: %v body=%s", err, w.Body)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows)=%d want=2 body=%s", len(rows), w.Body)
	}
	for _, row := range rows {
		if _, ok := row["emergency_drops"]; !ok {
			t.Errorf("row missing emergency_drops key: %v", row)
		}
		if _, ok := row["node_id"]; !ok {
			t.Errorf("row missing node_id key: %v", row)
		}
	}

	// 2. Unknown resolution → 400 with an error body.
	w = do("/api/nodes/posture/history?resolution=bogus")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bogus resolution: status=%d want=%d body=%s", w.Code, http.StatusBadRequest, w.Body)
	}
	var errBody map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil || errBody["error"] == "" {
		t.Fatalf("bogus resolution: body=%s err=%v", w.Body, err)
	}

	// 3. Explicit node_id + from/to → recorded filter carries them through.
	from := now.Add(-3 * time.Hour).Format(time.RFC3339)
	to := now.Format(time.RFC3339)
	w = do("/api/nodes/posture/history?node_id=edge-1&from=" + from + "&to=" + to)
	if w.Code != http.StatusOK {
		t.Fatalf("filtered: status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body)
	}
	f := ms.nodePosture.lastFilter
	if f.NodeID != "edge-1" {
		t.Errorf("filter.NodeID=%q want=edge-1", f.NodeID)
	}
	if f.From.IsZero() || f.To.IsZero() {
		t.Errorf("filter window zero: from=%v to=%v", f.From, f.To)
	}

	// 4. Default window: no from/to → From ≈1h ago, To non-zero.
	w = do("/api/nodes/posture/history")
	if w.Code != http.StatusOK {
		t.Fatalf("default window: status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body)
	}
	f = ms.nodePosture.lastFilter
	if f.From.IsZero() || f.To.IsZero() {
		t.Errorf("default window zero: from=%v to=%v", f.From, f.To)
	}
	if elapsed := time.Since(f.From); elapsed < 30*time.Minute || elapsed > 2*time.Hour {
		t.Errorf("default From=%v not ≈1h ago", f.From)
	}
}
