# Inline Posture History Implementation Plan (Spec Sections A + B)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist per-node inline posture counters to a time-series table, serve them via `GET /api/nodes/posture/history`, and chart them on the console Inline page and node drawer.

**Architecture:** A `PostureWriter` (DBWriter pattern: per-node "last sample wins" buffer, 15 s flush via pgx CopyFrom) hooked into the existing `onStats` callback writes `ts_node_posture`. A new repo + API endpoint bucket raw rows with `time_bucket` (no cagg — the table is small). The console computes per-second rates client-side from cumulative bucket maxima and renders them with the existing XChart component.

**Tech Stack:** Go 1.25 controller (gin, pgx v5, TimescaleDB-optional), Vue 3 + vitest console, demo scan gates.

**Spec:** `docs/superpowers/specs/2026-11-10-inline-surface-completion-design.md` §A/§B. Refinement vs spec: `cpu_util`/`xdp_mode` are **not** persisted in history (live posture endpoint already covers them; YAGNI). Everything else as specced.

**Branch:** `feature/inline-posture-history` off `main`.

**Reference patterns (read before starting):**
- Aggregation writer: `controller/internal/ingestion/db_writer.go`
- Repo + CopyFrom + time_bucket query: `controller/internal/store/postgres/stats.go`
- Handler param parsing: `controller/internal/api/timeseries.go`
- Migrations/policies: `controller/internal/store/postgres/postgres.go` (`migrations` ~line 927, `timescaleMigrations` ~1523, policy block ~248–298)
- Wiring: `controller/main.go` (`onStats` ~348, `dbWriter` ~141)
- Console chart contract: `controller/console/src/components/chart/XChart.vue` (props: `points: {time:number, values:Record<string,number>}[]`, `selected: string[]`, `slots: Record<string,number>` = key→color-slot index, `bounds: [start,end]`, `metric: string` used as unit suffix, `grain`, `loading`, `error`)

---

### Task 1: Store types, interface, migration, repo

**Files:**
- Modify: `controller/internal/store/repository.go:17-52` (Store interface) and the types region (~line 547–604)
- Modify: `controller/internal/store/postgres/postgres.go` (migrations list, timescaleMigrations, PGStore struct + New + accessor + AutoMigrate policy block)
- Create: `controller/internal/store/postgres/node_posture.go`
- Modify: the test mock store implementer found by `grep -rn "func (s \*MockStore) Stats()" controller/internal/tests/` (mock must stay compiling after the interface change)

- [ ] **Step 1: Add types + interface to `repository.go`** (insert next to `TimeseriesFilter`/`StatsRepo`):

```go
// PostureFilter selects a posture-history window.
type PostureFilter struct {
	NodeID     string
	From       time.Time
	To         time.Time
	Resolution string // "5s" | "1min" | "5min" (maps to time_bucket widths)
	Limit      int
}

// PosturePoint is one bucketed posture-history sample. Counters are cumulative
// (bucket max), matching how the node reports them.
type PosturePoint struct {
	Time                time.Time `json:"time"`
	NodeID              string    `json:"node_id"`
	FilterRules         uint64    `json:"filter_rules"`
	ValidatedClients    uint64    `json:"validated_clients"`
	SynCookiesReplied   uint64    `json:"syn_cookies_replied"`
	SynCookiesValidated uint64    `json:"syn_cookies_validated"`
	SynCookiesDropped   uint64    `json:"syn_cookies_dropped"`
	EmergencyDrops      uint64    `json:"emergency_drops"`
	BurstAlerts         uint64    `json:"burst_alerts"`
	RedirectOk          uint64    `json:"redirect_ok"`
	RedirectErr         uint64    `json:"redirect_err"`
	AFXDPActive         bool      `json:"af_xdp_active"`
	AFXDPUmemDrops      uint64    `json:"af_xdp_umem_drops"`
	AFXDPRX             uint64    `json:"af_xdp_rx"`
}

// NodePostureRepo persists and queries the ts_node_posture history.
type NodePostureRepo interface {
	BulkInsert(ctx context.Context, points []PosturePoint) error
	QueryHistory(ctx context.Context, filter PostureFilter) ([]PosturePoint, error)
}
```

Add `NodePosture() NodePostureRepo` to the `Store` interface (after `Stats() StatsRepo`, line 28).

- [ ] **Step 2: Add the migration DDL** to the `migrations` slice in `postgres.go`, right after the `ts_stats` extras migrations (after the `tcp_syn_bps` DO-block):

```go
	// v4.1: inline posture history (spec 2026-11-10 §A). Counters are cumulative;
	// af_xdp_active tracks socket health. Plain table; hypertable applied
	// separately when TimescaleDB is available.
	`CREATE TABLE IF NOT EXISTS ts_node_posture (
		time                 TIMESTAMPTZ NOT NULL,
		node_id              TEXT NOT NULL,
		filter_rules         BIGINT DEFAULT 0,
		validated_clients    BIGINT DEFAULT 0,
		syn_cookies_replied  BIGINT DEFAULT 0,
		syn_cookies_validated BIGINT DEFAULT 0,
		syn_cookies_dropped  BIGINT DEFAULT 0,
		emergency_drops      BIGINT DEFAULT 0,
		burst_alerts         BIGINT DEFAULT 0,
		redirect_ok          BIGINT DEFAULT 0,
		redirect_err         BIGINT DEFAULT 0,
		af_xdp_active        BOOLEAN DEFAULT FALSE,
		af_xdp_umem_drops    BIGINT DEFAULT 0,
		af_xdp_rx            BIGINT DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS ts_node_posture_node_time ON ts_node_posture (node_id, time DESC)`,
```

Add to `timescaleMigrations` (after the flow_logs block):

```go
	// v4.1: posture history hypertable
	`SELECT create_hypertable('ts_node_posture', 'time', if_not_exists => TRUE)`,
```

- [ ] **Step 3: Create `controller/internal/store/postgres/node_posture.go`:**

```go
package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nodePostureRepo struct{ pool *pgxpool.Pool }

// BulkInsert writes posture samples into ts_node_posture via CopyFrom.
func (r *nodePostureRepo) BulkInsert(ctx context.Context, points []store.PosturePoint) error {
	if len(points) == 0 {
		return nil
	}
	columns := []string{
		"time", "node_id",
		"filter_rules", "validated_clients",
		"syn_cookies_replied", "syn_cookies_validated", "syn_cookies_dropped",
		"emergency_drops", "burst_alerts", "redirect_ok", "redirect_err",
		"af_xdp_active", "af_xdp_umem_drops", "af_xdp_rx",
	}
	rows := make([][]any, len(points))
	for i, p := range points {
		rows[i] = []any{
			p.Time, p.NodeID,
			int64(p.FilterRules), int64(p.ValidatedClients),
			int64(p.SynCookiesReplied), int64(p.SynCookiesValidated), int64(p.SynCookiesDropped),
			int64(p.EmergencyDrops), int64(p.BurstAlerts), int64(p.RedirectOk), int64(p.RedirectErr),
			p.AFXDPActive, int64(p.AFXDPUmemDrops), int64(p.AFXDPRX),
		}
	}
	_, err := r.pool.CopyFrom(ctx, pgx.Identifier{"ts_node_posture"}, columns, pgx.CopyFromRows(rows))
	return err
}

// QueryHistory returns bucketed posture samples. Counters aggregate with max()
// (cumulative semantics), af_xdp_active with bool_or.
func (r *nodePostureRepo) QueryHistory(ctx context.Context, filter store.PostureFilter) ([]store.PosturePoint, error) {
	bucket := "1 minute"
	switch filter.Resolution {
	case "5s":
		bucket = "15 seconds"
	case "5min":
		bucket = "5 minutes"
	}

	var conds []string
	var args []any
	argN := 1
	if !filter.From.IsZero() {
		conds = append(conds, fmt.Sprintf("time >= $%d", argN))
		args = append(args, filter.From)
		argN++
	}
	if !filter.To.IsZero() {
		conds = append(conds, fmt.Sprintf("time <= $%d", argN))
		args = append(args, filter.To)
		argN++
	}
	if filter.NodeID != "" {
		conds = append(conds, fmt.Sprintf("node_id = $%d", argN))
		args = append(args, filter.NodeID)
		argN++
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	limit := clampLimit(filter.Limit)

	q := fmt.Sprintf(`
		SELECT time_bucket('%s', time) AS bucket, node_id,
			   max(filter_rules)::BIGINT, max(validated_clients)::BIGINT,
			   max(syn_cookies_replied)::BIGINT, max(syn_cookies_validated)::BIGINT,
			   max(syn_cookies_dropped)::BIGINT, max(emergency_drops)::BIGINT,
			   max(burst_alerts)::BIGINT, max(redirect_ok)::BIGINT, max(redirect_err)::BIGINT,
			   bool_or(af_xdp_active), max(af_xdp_umem_drops)::BIGINT, max(af_xdp_rx)::BIGINT
		FROM ts_node_posture%s
		GROUP BY bucket, node_id
		ORDER BY bucket
		LIMIT %d`, bucket, where, limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []store.PosturePoint
	for rows.Next() {
		var p store.PosturePoint
		if err := rows.Scan(&p.Time, &p.NodeID,
			&p.FilterRules, &p.ValidatedClients,
			&p.SynCookiesReplied, &p.SynCookiesValidated, &p.SynCookiesDropped,
			&p.EmergencyDrops, &p.BurstAlerts, &p.RedirectOk, &p.RedirectErr,
			&p.AFXDPActive, &p.AFXDPUmemDrops, &p.AFXDPRX); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}
```

- [ ] **Step 4: Register in `PGStore`:** struct field `nodePosture *nodePostureRepo`; in `New()`: `s.nodePosture = &nodePostureRepo{pool: pool}`; accessor `func (s *PGStore) NodePosture() store.NodePostureRepo { return s.nodePosture }` (next to `Stats()`).

- [ ] **Step 5: Fix every `store.Store` implementer** broken by the new method: run `grep -rn "Stats() store.StatsRepo" controller --include=*.go` — for each implementer other than `PGStore` (the tests mock store), add:

```go
func (s *MockStore) NodePosture() store.NodePostureRepo { return s.nodePosture }
```

with a `nodePosture` field holding a trivial in-memory fake (`BulkInsert` appends to a slice, `QueryHistory` returns nil, expose the slice for assertions if the mock already does that for stats — otherwise return a `&fakeNodePostureRepo{}` zero-value stub).

- [ ] **Step 6: Build + vet:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go build ./... && GOTOOLCHAIN=go1.25.0 go vet ./internal/store/...`
Expected: no errors.

- [ ] **Step 7: Static migration pin test** — append to the existing static test file that pins migration SQL (find via `grep -rln "ts_stats" controller/internal/store/postgres/*_test.go | head -1`; if none, create `controller/internal/store/postgres/posture_migration_test.go`):

```go
package postgres

import (
	"regexp"
	"testing"
)

func TestNodePostureMigrationPresent(t *testing.T) {
	joined := strings.Join(migrations, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS ts_node_posture",
		"ts_node_posture_node_time",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("migrations missing %q", want)
		}
	}
	// Idempotency: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS only.
	re := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS ts_node_posture.*?CREATE INDEX IF NOT EXISTS ts_node_posture_node_time`)
	if !re.MatchString(joined) {
		t.Error("ts_node_posture DDL must be guarded with IF NOT EXISTS")
	}
}
```

(Add `"strings"` to imports; adapt package/identifier names to the file you appended to.)

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go test ./internal/store/postgres/ -run TestNodePostureMigration -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add controller/internal/store/
git commit -m "feat(store): ts_node_posture history table + NodePostureRepo"
```

---

### Task 2: PostureWriter (ingestion) + wiring

**Files:**
- Create: `controller/internal/ingestion/posture_writer.go`
- Create: `controller/internal/ingestion/posture_writer_test.go`
- Modify: `controller/main.go` (~141 wiring, ~350 onStats)

- [ ] **Step 1: Write the failing test** `posture_writer_test.go`:

```go
package ingestion

import (
	"context"
	"testing"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type fakePostureRepo struct{ inserted []store.PosturePoint }

func (f *fakePostureRepo) BulkInsert(ctx context.Context, points []store.PosturePoint) error {
	f.inserted = append(f.inserted, points...)
	return nil
}
func (f *fakePostureRepo) QueryHistory(ctx context.Context, filter store.PostureFilter) ([]store.PosturePoint, error) {
	return nil, nil
}

func TestPostureWriterLastSampleWins(t *testing.T) {
	repo := &fakePostureRepo{}
	w := NewPostureWriter(repo, 15*time.Second)
	w.Enqueue("edge-1", &pb.StatsReport{Posture: &pb.NodePosture{EmergencyDrops: 10}})
	w.Enqueue("edge-1", &pb.StatsReport{Posture: &pb.NodePosture{EmergencyDrops: 25}})
	w.Enqueue("edge-2", &pb.StatsReport{Posture: &pb.NodePosture{EmergencyDrops: 7}})
	w.Enqueue("edge-1", &pb.StatsReport{Posture: nil}) // posture-less report is a no-op

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if len(repo.inserted) != 2 {
		t.Fatalf("want 2 rows (one per node), got %d", len(repo.inserted))
	}
	byNode := map[string]store.PosturePoint{}
	for _, p := range repo.inserted {
		byNode[p.NodeID] = p
	}
	if got := byNode["edge-1"].EmergencyDrops; got != 25 {
		t.Errorf("edge-1: want last sample 25, got %d", got)
	}
	if got := byNode["edge-2"].EmergencyDrops; got != 7 {
		t.Errorf("edge-2: want 7, got %d", got)
	}
	if byNode["edge-1"].Time.Location() != time.UTC {
		t.Errorf("flush time must be UTC-truncated, got %v", byNode["edge-1"].Time)
	}
}
```

- [ ] **Step 2: Run it, verify compile failure:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go test ./internal/ingestion/ -run TestPostureWriterLastSampleWins -count=1`
Expected: FAIL — `undefined: NewPostureWriter`.

- [ ] **Step 3: Implement `posture_writer.go`:**

```go
package ingestion

import (
	"context"
	"log"
	"sync"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// PostureWriter persists per-node inline posture counters into ts_node_posture.
// Counters are cumulative, so the writer keeps only the LAST sample per node
// per flush window ("last sample wins") — no averaging, unlike DBWriter.
type PostureWriter struct {
	repo     store.NodePostureRepo
	interval time.Duration

	mu      sync.Mutex
	pending map[string]store.PosturePoint
}

func NewPostureWriter(repo store.NodePostureRepo, interval time.Duration) *PostureWriter {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &PostureWriter{
		repo:     repo,
		interval: interval,
		pending:  make(map[string]store.PosturePoint),
	}
}

// Enqueue records the latest posture of a Node. Reports without a posture
// (flow-only Nodes) are ignored.
func (w *PostureWriter) Enqueue(nodeID string, report *pb.StatsReport) {
	post := report.GetPosture()
	if nodeID == "" || post == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending[nodeID] = store.PosturePoint{
		NodeID:              nodeID,
		FilterRules:         post.GetFilterRules(),
		ValidatedClients:    post.GetValidatedClients(),
		SynCookiesReplied:   post.GetSynCookiesReply(),
		SynCookiesValidated: post.GetSynCookiesValidated(),
		SynCookiesDropped:   post.GetSynCookiesDropped(),
		EmergencyDrops:      post.GetEmergencyDrops(),
		BurstAlerts:         post.GetBurstAlerts(),
		RedirectOk:          post.GetRedirectOk(),
		RedirectErr:         post.GetRedirectErr(),
		AFXDPActive:         post.GetAfXdpActive(),
		AFXDPUmemDrops:      post.GetAfXdpUmemDrops(),
		AFXDPRX:             post.GetAfXdpRx(),
	}
}

// Run flushes every interval. Blocks until ctx is cancelled.
func (w *PostureWriter) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.flush(context.Background())
			return
		case <-ticker.C:
			w.flush(ctx)
		}
	}
}

func (w *PostureWriter) flush(ctx context.Context) {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return
	}
	batch := make([]store.PosturePoint, 0, len(w.pending))
	for _, p := range w.pending {
		p.Time = time.Now().UTC().Truncate(w.interval)
		batch = append(batch, p)
	}
	w.pending = make(map[string]store.PosturePoint)
	w.mu.Unlock()

	if err := w.repo.BulkInsert(ctx, batch); err != nil {
		log.Printf("posture_writer: insert %d rows failed: %v", len(batch), err)
	}
}
```

- [ ] **Step 4: Run test → PASS:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go test ./internal/ingestion/ -run TestPostureWriterLastSampleWins -count=1`
Expected: PASS.

- [ ] **Step 5: Wire in `main.go`:** after the `dbWriter` block (~line 141):

```go
	postureWriter := ingestion.NewPostureWriter(db.NodePosture(), 15*time.Second)
	go postureWriter.Run(ctx)
```

In `onStats` (first lines, next to `dbWriter.Enqueue`):

```go
		postureWriter.HandleStats(nodeID, report)
```

Wait — use `Enqueue`, not HandleStats (that name belongs to statsWriter):

```go
		postureWriter.Enqueue(nodeID, report)
```

- [ ] **Step 6: Build + package tests:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go build ./... && GOTOOLCHAIN=go1.25.0 go test ./internal/ingestion/ -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add controller/internal/ingestion/posture_writer.go controller/internal/ingestion/posture_writer_test.go controller/main.go
git commit -m "feat(ingestion): PostureWriter persists inline posture history"
```

---

### Task 3: Retention config + policies + cleaner fallback

**Files:**
- Modify: `controller/internal/config/config.go` (Retention struct ~line 61, defaults ~182, validation ~276)
- Modify: `controller/internal/store/postgres/postgres.go` (AutoMigrate policy block ~248–298)
- Modify: `controller/internal/retention/cleaner.go` (+ its cfg struct and the main.go construction site)

- [ ] **Step 1: Config.** In the `Retention` struct next to `FlowLogsDays`:

```go
	PostureHistoryDays   int `yaml:"posture_history_days"`   // delete ts_node_posture older than N days (default 7); 0 = keep forever
```

In the defaults block next to `FlowLogsDays: 7`:

```go
			PostureHistoryDays:   7,
```

In validation next to the `FlowLogsDays` check:

```go
	if c.Retention.PostureHistoryDays < 0 {
		return fmt.Errorf("retention.posture_history_days must be >= 0, got %d", c.Retention.PostureHistoryDays)
	}
```

- [ ] **Step 2: Timescale retention policy** in `AutoMigrate` (postgres.go), after the FlowLogs policies:

```go
	if ret.PostureHistoryDays > 0 {
		s.applyRetentionPolicy(ctx, "ts_node_posture", ret.PostureHistoryDays)
	} else if s.IsHypertable("ts_node_posture") {
		s.removeRetentionPolicy(ctx, "ts_node_posture")
	}
```

- [ ] **Step 3: Row-delete fallback** in `retention/cleaner.go`: add `PostureHistoryDays int` and `PostureHypertable bool` to the cleaner cfg struct; in `cleanup`, after the ts_stats block:

```go
	if c.cfg.PostureHistoryDays > 0 && !c.cfg.PostureHypertable {
		n, err := c.deleteOld(ctx, "ts_node_posture", "time", c.cfg.PostureHistoryDays)
		if err != nil {
			log.Printf("retention: ts_node_posture cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: ts_node_posture deleted %d rows older than %d days", n, c.cfg.PostureHistoryDays)
			total += n
		}
	}
```

Map the two fields at the Cleaner construction site in `main.go` (mirror how `TSStatsDays`/`TSStatsHypertable` are passed: `PostureHistoryDays: cfg.Retention.PostureHistoryDays, PostureHypertable: db.IsHypertable("ts_node_posture")`).

- [ ] **Step 4: Verify:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go build ./... && GOTOOLCHAIN=go1.25.0 go test ./internal/config/ ./internal/retention/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add controller/internal/config/config.go controller/internal/store/postgres/postgres.go controller/internal/retention/ controller/main.go
git commit -m "feat(retention): posture_history_days policy for ts_node_posture"
```

---

### Task 4: History API endpoint

**Files:**
- Create: `controller/internal/api/posture_history.go`
- Create: `controller/internal/api/posture_history_test.go` (or append to the existing inline API smoke test file if the mock fixture there is more convenient)
- Modify: `controller/internal/api/router.go:183-186` (route registration)

- [ ] **Step 1: Write the failing test** (uses the same mock-store fixture as `dao14d1_api_test.go:469`):

```go
package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestPostureHistoryAPI(t *testing.T) {
	handler := api.PostureHistoryHandler()
	if handler == nil {
		t.Fatal("handler factory must not return nil")
	}
	_ = store.PostureFilter{From: time.Now().Add(-time.Hour)} // type smoke
}
```

Replace this sketch with the project's real router-test idiom: copy the fixture setup from `dao14d1_api_test.go:1100-1110` (the G4 inline smoke test) and add these cases:

1. `GET /api/nodes/posture/history` with the mock store returning two `store.PosturePoint` rows → expect 200, JSON array of 2 objects with `"emergency_drops"` and `"node_id"` keys.
2. `?resolution=bogus` → 400 with an error body.
3. `?node_id=edge-1` → the mock repo asserts it received `NodeID: "edge-1"`.

(The mock repo from Task 1 Step 5 must record the filter it received; extend it if needed.)

- [ ] **Step 2: Run → verify it fails:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go test ./internal/tests/ -run TestPostureHistoryAPI -count=1`
Expected: FAIL — `deps.Store.NodePosture` undefined or 404 on the route.

- [ ] **Step 3: Implement `posture_history.go`:**

```go
package api

import (
	"net/http"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

// postureHistoryLimit mirrors the resolution-dependent caps of queryTimeseries.
func postureHistoryLimit(resolution string) int {
	switch resolution {
	case "5s":
		return 1920 // 8h of 15s buckets
	case "5min":
		return 2016 // 7d of 5min buckets
	default:
		return 2880 // 48h of 1min buckets
	}
}

// postureHistory serves GET /api/nodes/posture/history.
func postureHistory(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.Store == nil {
			errResponse(c, http.StatusServiceUnavailable, "store unavailable")
			return
		}
		resolution := c.DefaultQuery("resolution", "1min")
		switch resolution {
		case "5s", "1min", "5min":
		default:
			errResponse(c, http.StatusBadRequest, "resolution must be '5s', '1min', or '5min'")
			return
		}
		filter := store.PostureFilter{
			NodeID:     c.Query("node_id"),
			Resolution: resolution,
			Limit:      postureHistoryLimit(resolution),
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.From = t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.To = t
			}
		}
		if filter.From.IsZero() {
			filter.From = time.Now().Add(-1 * time.Hour)
		}
		if filter.To.IsZero() {
			filter.To = time.Now()
		}
		points, err := deps.Store.NodePosture().QueryHistory(c.Request.Context(), filter)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, points)
	}
}
```

- [ ] **Step 4: Register the route** in `router.go`, directly under the existing inline block (before `/nodes/:id/tls`):

```go
		api.GET("/nodes/posture/history", postureHistory(deps))
```

- [ ] **Step 5: Run test → PASS:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go test ./internal/tests/ -run TestPostureHistoryAPI -count=1`
Expected: PASS.

- [ ] **Step 6: Full controller suite:**

Run: `cd controller && GOTOOLCHAIN=go1.25.0 go test ./... -count=1`
Expected: PASS (pre-existing failures in unrelated packages must not increase — record the baseline first with `go test ./... -count=1 2>&1 | tail -20` if unsure).

- [ ] **Step 7: Commit**

```bash
git add controller/internal/api/
git commit -m "feat(api): GET /api/nodes/posture/history"
```

---

### Task 5: Demo mock + gates

**Files:**
- Modify: `controller/console/demo/server.ts` (add the history handler next to the three inline handlers added in `f6d8033` — mirror their exact style)
- Modify: `controller/console/tests/demo-gates.test.ts` (GET route count 57 → 58)

- [ ] **Step 1: Read the existing handlers** (`grep -n "nodes/posture" demo/server.ts`) and add the sibling handler immediately after the `/api/nodes/posture` one, generating deterministic sample data:

```ts
  if (url.pathname === '/api/nodes/posture/history') {
    const now = Date.now()
    const step = 60000
    const rows = []
    for (let i = 24; i >= 0; i--) {
      const t = new Date(now - i * step).toISOString()
      const base = (24 - i) * 3
      rows.push({ time: t, node_id: 'edge-a', filter_rules: 2, validated_clients: 40 + base,
        syn_cookies_replied: 120 + base * 2, syn_cookies_validated: 100 + base * 2,
        syn_cookies_dropped: 12 + (i % 3), emergency_drops: i > 18 ? (i - 18) * 250 : 0,
        burst_alerts: i > 18 ? 2 : 0, redirect_ok: 500 + base, redirect_err: 0,
        af_xdp_active: true, af_xdp_umem_drops: 0, af_xdp_rx: 90000 + base * 100 })
    }
    return json(rows)
  }
```

(Adjust `json(...)`/response helper names to whatever the file already uses.)

- [ ] **Step 2: Update the gate count** in `tests/demo-gates.test.ts` (`57` → `58` in the G3 assertion; also update the comment if one lists the routes).

- [ ] **Step 3: Run the gates exactly as CI does:**

Run: `cd controller/console && export XSIGHT_VERSION=$(git describe --always) && npm run build:demo && node demo/scan.mjs --prod dist --demo demo-dist && npx vitest run tests/demo-gates.test.ts`
Expected: scan passes with `"endpoints":58,"failures":[]`, gates PASS.

- [ ] **Step 4: Commit**

```bash
git add controller/console/demo/server.ts controller/console/tests/demo-gates.test.ts
git commit -m "feat(demo): mock /api/nodes/posture/history, bump gate to 58"
```

---

### Task 6: Console — history data module (pure functions, TDD)

**Files:**
- Create: `controller/console/src/views/inline/history.ts`
- Create: `controller/console/tests/inline-history.test.ts`

- [ ] **Step 1: Write the failing test** `inline-history.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { posturePoints, PostureRow } from '../src/views/inline/history'

const row = (t: string, over: Partial<PostureRow> = {}): PostureRow => ({
  time: t, node_id: 'edge-a', filter_rules: 2, validated_clients: 10,
  syn_cookies_replied: 100, syn_cookies_validated: 90, syn_cookies_dropped: 5,
  emergency_drops: 0, burst_alerts: 0, redirect_ok: 1, redirect_err: 0,
  af_xdp_active: true, af_xdp_umem_drops: 0, af_xdp_rx: 1000, ...over,
})

describe('posturePoints', () => {
  it('sums nodes per bucket and computes per-second deltas', () => {
    const rows: PostureRow[] = [
      row('2026-01-01T00:00:00Z', { emergency_drops: 100 }),
      row('2026-01-01T00:01:00Z', { emergency_drops: 250 }),
      row('2026-01-01T00:02:00Z', { emergency_drops: 310 }),
    ]
    const pts = posturePoints(rows, '')
    expect(pts).toHaveLength(3)
    expect(pts[0].values.emergency).toBe(0) // first bucket has no predecessor
    expect(Math.round(pts[1].values.emergency)).toBe(Math.round(150 / 60))
    expect(Math.round(pts[2].values.emergency)).toBe(Math.round(60 / 60))
  })

  it('treats counter resets as zero, not negative', () => {
    const rows: PostureRow[] = [
      row('2026-01-01T00:00:00Z', { emergency_drops: 500 }),
      row('2026-01-01T00:01:00Z', { emergency_drops: 3 }), // node restarted
    ]
    const pts = posturePoints(rows, '')
    expect(pts[1].values.emergency).toBe(0)
  })

  it('filters by node when requested', () => {
    const rows: PostureRow[] = [
      row('2026-01-01T00:00:00Z'),
      row('2026-01-01T00:00:00Z', { node_id: 'edge-b', emergency_drops: 60 }),
    ]
    const pts = posturePoints(rows, 'edge-b')
    expect(pts).toHaveLength(1)
    expect(pts[0].time).toBe(Date.parse('2026-01-01T00:00:00Z'))
  })

  it('returns [] for empty input', () => {
    expect(posturePoints([], '')).toEqual([])
  })
})
```

(Note: remove the accidental `getic` token if it slips in — the line must read `expect(pts[0].time)...`.)

- [ ] **Step 2: Run → FAIL:**

Run: `cd controller/console && npx vitest run tests/inline-history.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `history.ts`:**

```ts
// Inline posture history: fetch + normalization for the Inline page chart.
// Counters are cumulative; the chart wants per-second event rates, so buckets
// are summed across nodes (or filtered to one) and turned into deltas.
export interface PostureRow {
  time: string
  node_id: string
  filter_rules: number
  validated_clients: number
  syn_cookies_replied: number
  syn_cookies_validated: number
  syn_cookies_dropped: number
  emergency_drops: number
  burst_alerts: number
  redirect_ok: number
  redirect_err: number
  af_xdp_active: boolean
  af_xdp_umem_drops: number
  af_xdp_rx: number
}

export interface Point { time: number; values: Record<string, number> }

const COUNTERS = ['emergency', 'cookies_ok', 'cookies_drop', 'umem'] as const

function counterValue(r: PostureRow): Record<string, number> {
  return {
    emergency: r.emergency_drops,
    cookies_ok: r.syn_cookies_validated,
    cookies_drop: r.syn_cookies_dropped,
    umem: r.af_xdp_umem_drops,
  }
}

// posturePoints converts raw history rows into XChart points. nodeFilter ''
// sums all nodes per bucket; a node id restricts to that node.
export function posturePoints(rows: PostureRow[], nodeFilter: string): Point[] {
  if (!rows.length) return []
  const filtered = nodeFilter ? rows.filter(r => r.node_id === nodeFilter) : rows
  const byTime = new Map<number, Record<string, number>>()
  for (const r of filtered) {
    const t = Date.parse(r.time)
    if (Number.isNaN(t)) continue
    const acc = byTime.get(t)
    const vals = counterValue(r)
    if (!acc) { byTime.set(t, vals); continue }
    for (const k of COUNTERS) acc[k] = (acc[k] ?? 0) + (vals[k] ?? 0)
  }
  const times = [...byTime.keys()].sort((a, b) => a - b)
  const out: Point[] = []
  let prev: Record<string, number> | null = null
  let prevTime = 0
  for (const t of times) {
    const cur = byTime.get(t)!
    const values: Record<string, number> = {}
    for (const k of COUNTERS) {
      const c = cur[k] ?? 0
      values[k] = prev && c >= (prev[k] ?? 0)
        ? (c - (prev[k] ?? 0)) / Math.max(1, (t - prevTime) / 1000)
        : 0 // first bucket or counter reset (node restart)
    }
    out.push({ time: t, values })
    prev = cur
    prevTime = t
  }
  return out
}
```

Also delete the now-unneeded note about `CounterKey` in `history.ts` — the type line is dropped entirely (it was unused).

- [ ] **Step 4: Run → PASS:**

Run: `cd controller/console && npx vitest run tests/inline-history.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add controller/console/src/views/inline/history.ts controller/console/tests/inline-history.test.ts
git commit -m "feat(console): posture history normalization with rate deltas"
```

---

### Task 7: Console — chart panel on the Inline page + i18n

**Files:**
- Modify: `controller/console/src/views/inline/Inline.vue`
- Modify: `controller/console/src/i18n/en.ts` (inline section ~line 1175) and `ar.ts` (same section)
- Test: run existing `tests/inline57.test.ts` — it stubs the two fetches; the new third fetch must not break it (extend its stub list if the test asserts fetch counts)

- [ ] **Step 1: i18n keys.** In `en.ts` inside `inline: { ... }`:

```ts
    histTitle: "Posture History",
    histHint: "rates from cumulative counters",
    histNodeAll: "All nodes",
    seriesEmergency: "Emergency drops",
    seriesCookiesOk: "Cookies validated",
    seriesCookiesDrop: "Cookies dropped",
    seriesUmem: "UMEM drops",
```

In `ar.ts` the same keys:

```ts
    histTitle: "سجل وضعية العقد",
    histHint: "معدلات محسوبة من العدادات التراكمية",
    histNodeAll: "جميع العقد",
    seriesEmergency: "إسقاطات الطوارئ",
    seriesCookiesOk: "كوكيز موثّقة",
    seriesCookiesDrop: "كوكيز مرفوضة",
    seriesUmem: "إسقاطات UMEM",
```

- [ ] **Step 2: Inline.vue script additions.** New imports and state (after the existing shallowRefs):

```ts
import XChart from '../../components/chart/XChart.vue'
import { posturePoints, type PostureRow } from './history'

const histRows = shallowRef<PostureRow[]>([])
const histRange = ref<'1h' | '6h' | '24h'>('1h')
const histNode = ref('') // '' = all nodes
const histLoading = ref(false)
const histError = ref('')

const HIST_RANGES: Record<'1h' | '6h' | '24h', { ms: number; resolution: string; poll: number }> = {
  '1h': { ms: 3600e3, resolution: '1min', poll: 10000 },
  '6h': { ms: 6 * 3600e3, resolution: '5min', poll: 60000 },
  '24h': { ms: 24 * 3600e3, resolution: '5min', poll: 60000 },
}

async function fetchHistory() {
  const cfg = HIST_RANGES[histRange.value]
  const params = new URLSearchParams({
    from: new Date(Date.now() - cfg.ms).toISOString(),
    resolution: cfg.resolution,
  })
  if (histNode.value) params.set('node_id', histNode.value)
  histLoading.value = true
  return request<PostureRow[]>(`/api/nodes/posture/history?${params}`).then(r => {
    histRows.value = r ?? []
    histError.value = ''
  }).catch(e => { histError.value = e instanceof Error ? e.message : String(e) })
    .finally(() => { histLoading.value = false })
}

usePoll(fetchHistory, HIST_RANGES[histRange.value].poll,
  () => {}, () => {})
// re-fetch when the range or node filter changes
import { watch } from 'vue'
watch([histRange, histNode], () => { fetchHistory() })

const histBounds = computed<[number, number]>(() => [Date.now() - HIST_RANGES[histRange.value].ms, Date.now()])
const histPoints = computed(() => posturePoints(histRows.value, histNode.value))
const histSelected = ['emergency', 'cookies_ok', 'cookies_drop', 'umem']
const histSlots = { emergency: 0, cookies_ok: 1, cookies_drop: 2, umem: 3 }
```

(`computed` is already imported; `watch` may need adding to the existing `import { computed, ref, shallowRef } from 'vue'` line.)

- [ ] **Step 3: Template.** Insert a new panel between the KPI grid and the mitigations panel:

```html
    <div class="panel">
      <div class="panel-head">
        <h2>{{ t('inline.histTitle') }}</h2>
        <span class="sub">{{ t('inline.histHint') }}</span>
        <span class="toolbar">
          <select v-model="histNode" class="input sm">
            <option value="">{{ t('inline.histNodeAll') }}</option>
            <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.id }}</option>
          </select>
          <select v-model="histRange" class="input sm">
            <option value="1h">1h</option>
            <option value="6h">6h</option>
            <option value="24h">24h</option>
          </select>
        </span>
      </div>
      <XChart :points="histPoints" :selected="histSelected" :slots="histSlots"
        :bounds="histBounds" metric="events/s" :grain="60000"
        :loading="histLoading" :error="histError" />
    </div>
```

XChart's legend renders the raw series keys from `selected`. If raw keys look wrong in the browser preview, switch `histSelected` to localized display labels and map them in `posturePoints` — but only do this if the raw keys are actually visible in the legend; do not add the mapping preemptively. If the select elements use a different shared class than `input sm` in this codebase, copy the class from any existing select in `views/traffic/Traffic.vue`.

- [ ] **Step 4: Typecheck + unit tests + build:**

Run: `cd controller/console && npm run build && npx vitest run tests/inline57.test.ts tests/inline-history.test.ts tests/demo-gates.test.ts`
Expected: build succeeds; tests PASS (extend the fetch stubs in `inline57.test.ts` if it asserts on unmocked URLs — add `/api/nodes/posture/history` → `[]` stub).

- [ ] **Step 5: Commit**

```bash
git add controller/console/src/views/inline/ controller/console/src/i18n/
git commit -m "feat(console): posture history chart on the Inline page"
```

---

### Task 8: Node drawer posture section (spec §B)

**Files:**
- Modify: `controller/console/src/views/nodes/Detail.vue`
- Modify: i18n `en.ts` / `ar.ts` (new `nodes.posture*` keys)
- Test: extend or add `controller/console/tests/node-detail-posture.test.ts`

- [ ] **Step 1: Failing vitest** — mount Detail.vue with a stubbed `/api/nodes/:id/posture` returning:

```json
{"node_id":"edge-a","available":true,"posture":{"xdp_mode":"driver","inline_enabled":true,"filter_rules":3,"validated_clients":12,"syn_cookies_replied":100,"syn_cookies_validated":90,"syn_cookies_dropped":4,"emergency_drops":250,"burst_alerts":2,"redirect_ok":10,"redirect_err":0,"af_xdp_active":true,"af_xdp_umem_drops":0,"af_xdp_rx":8000,"cpu_pins":[2,3],"cpu_util":[0.11,0.04],"updated_at":"2026-01-01T00:00:00Z"}}
```

Assert the rendered section shows `driver`, the cookie triple `100 / 90 / 4`, and `250` emergency drops. Follow the mounting/stubbing idiom of the existing `tests/inline57.test.ts`.

- [ ] **Step 2: Run → FAIL**, then implement: in Detail.vue fetch `GET /api/nodes/:id/posture` once on open (and refresh on the drawer's existing poll if it has one; otherwise poll every 10 s while open), render an "Inline posture" section: inline on/off + `xdp_mode`, filter rules + validated clients, cookie reply/valid/drop triple, emergency drops + burst alerts, AF_XDP dot + rx + UMEM drops, CPU pins/util, `updated_at` with a staleness class (`stale` when `Date.now() - Date.parse(updated_at) > 30000`). When `available === false` render the muted hint `t('nodes.postureUnavailable')`.

i18n keys (en):

```ts
    postureTitle: "Inline posture",
    postureUnavailable: "No inline posture reported",
    postureStale: "stale",
```

(ar):

```ts
    postureTitle: "وضعية inline",
    postureUnavailable: "لم يتم الإبلاغ عن وضعية inline",
    postureStale: "قديمة",
```

- [ ] **Step 3: Run test → PASS**, then full console verification:

Run: `cd controller/console && npm run build && npx vitest run`
Expected: build PASS; new tests PASS; pre-existing failure count must not increase (the suite has ~788 documented pre-existing failures — compare against the count on `main` before starting, `git stash`-free baseline run).

- [ ] **Step 4: Commit**

```bash
git add controller/console/src/views/nodes/ controller/console/src/i18n/ controller/console/tests/
git commit -m "feat(console): per-node inline posture in the node drawer"
```

---

### Task 9: Docs + final verification

**Files:**
- Modify: `docs/INLINE.md` §6 API table (add the history row)
- Full-repo verification

- [ ] **Step 1: Docs.** Add to the §6 table in `docs/INLINE.md`:

```markdown
| `GET` | `/api/nodes/posture/history` | bucketed posture-counter history (charting) |
```

and extend the console paragraph: "…posture table (…). A Posture History chart plots per-second emergency-drop, SYN-cookie and UMEM-drop rates over 1 h/6 h/24 h; the Node drawer shows the live per-Node posture."

- [ ] **Step 2: Full verification suite:**

```bash
cd controller && GOTOOLCHAIN=go1.25.0 go test ./... -count=1
cd ../shared && GOTOOLCHAIN=go1.25.0 go test ./... -count=1
cd ../controller/console && npm run build && npx vitest run tests/demo-gates.test.ts tests/inline57.test.ts tests/inline-history.test.ts
cd ../../controller/console && export XSIGHT_VERSION=$(git describe --always) && npm run build:demo && node demo/scan.mjs --prod dist --demo demo-dist
```

Expected: Go suites green; console build + targeted vitest green; demo scan `passed: true` with 58 endpoints.

- [ ] **Step 3: Commit docs + push branch:**

```bash
git add docs/INLINE.md
git commit -m "docs: posture history endpoint + chart in INLINE.md"
git push -u origin feature/inline-posture-history
```

---

## Self-Review Notes

- Spec §A coverage: storage (Task 1), writer (Task 2), retention (Task 3), API (Task 4), chart (Tasks 6–7). §B: Task 8. Deviation (cpu_util/xdp_mode not persisted) documented in the header.
- Demo gate interlock handled in Task 5 (route count 57→58) so CI stays green.
- Known pre-existing debt that must not grow: console suite failures (~788), demo-gates "G3 respects exact requested bounds" clock flake.
- Execution environment facts: controller tests need `GOTOOLCHAIN=go1.25.0`; node/go on PATH via `/usr/local/go/bin`; use `rtk` wrappers for git in this environment.
