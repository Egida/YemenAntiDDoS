# Inline Surface Completion — Console & Controller (v4.1)

Status: approved design, 2026-11-10. Builds on the phase 0–5 inline data plane
(docs/INLINE.md, docs/L7.md) and closes the gaps the completion audit found
between what the Node/BPF layer provides and what the Controller/Console expose.

## Context

The Node and the Controller's auto-mitigation engine are complete (broad →
narrow → rebreadth, withdraw, reconcile, AF_XDP gating). The audit found these
gaps:

1. Posture counters are memory-only — lost on node disconnect, no history, no
   charts.
2. `GET /api/nodes/:id/posture` exists but no UI consumes it.
3. Inline rules cannot be managed manually — mitigations are auto-only.
4. `pb.NodePostureConfig` (WatchConfig field 5) is implemented node-side
   (`applyPostureConfig`, node/inline.go:511) but never sent by the Controller.
5. docs/INLINE.md §2 documents a tri-state `default_action` drop catch-all that
   the push path does not implement (snapshots always carry `"pass"`).
6. Demo/dev-mock fixtures for the inline endpoints are missing or partial.

## Goals / Non-goals

Goals: sections A–F below, landed in that order as independent units.

Non-goals: redesigning the mitigation engine; multi-controller HA; L7 changes;
new node YAML surface beyond what section D pushes.

---

## A. Posture history (persistence + API + charts)

**Storage.** New hypertable `ts_node_posture` in the `migrations` list
(controller/internal/store/postgres/postgres.go):

```sql
CREATE TABLE IF NOT EXISTS ts_node_posture (
  time timestamptz NOT NULL,
  node_id text NOT NULL,
  filter_rules bigint, validated_clients bigint,
  syn_cookies_replied bigint, syn_cookies_validated bigint,
  syn_cookies_dropped bigint, emergency_drops bigint,
  burst_alerts bigint, redirect_ok bigint, redirect_err bigint,
  af_xdp_rx bigint, af_xdp_umem_drops bigint,
  af_xdp_active boolean,
  xdp_mode text,
  cpu_util jsonb
);
CREATE INDEX IF NOT EXISTS ts_node_posture_node_time ON ts_node_posture (node_id, time DESC);
```

Timescale guard identical to `ts_stats`: hypertable creation only when
TimescaleDB is present; plain table otherwise.

**Writer.** `PostureWriter` in controller/internal/ingestion (DBWriter
pattern): per-node ring, keeps the last sample per flush window (counters are
cumulative — last wins), flush every 15 s via pgx CopyFrom. Hooked where
`UpdatePosture` is called (grpc_handler.go:369–372) so every StatsReport
contributes without extra wire traffic.

**Retention.** `posture_history_days` controller config (default 7): Timescale
drop-chunks policy when available, row-delete fallback in retention/cleaner.go
otherwise.

**API.** `GET /api/nodes/posture/history` — params `node_id` (repeatable),
`from`/`to` (RFC3339, default last 1 h), `resolution` `5s|1min|5min`
(default `1min`), resolution-dependent LIMIT as in timeseries.go. Response:
flat row array matching `ts_stats` conventions.

**Console.** Inline page gains a chart section: XChart + range selector
(1h/6h/24h, poll grain as overview/data.ts) plotting client-computed rates
(delta of cumulative counters): emergency drops/s, SYN cookies validated/s and
dropped/s, UMEM drops/s, with a node filter.

## B. Per-node posture drawer

Node `Detail.vue` gains an "Inline posture" section: fetch
`GET /api/nodes/:id/posture` (200 with `available:false` handled as an empty
hint), render inline on/off, `xdp_mode`, filter rules, validated clients,
cookie replied/validated/dropped, emergency drops, burst alerts, AF_XDP health
+ rx + UMEM drops, CPU pins/util, `updated_at` with a staleness pill (stale
when > 30 s old). Plus an emergency-drops sparkline from the history endpoint.

## C. Manual inline rules (CRUD)

**Storage.** `inline_manual_rules`:

```sql
CREATE TABLE IF NOT EXISTS inline_manual_rules (
  id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL,
  note text NOT NULL DEFAULT '',
  dst_ip text NOT NULL, dst_prefix_len int NOT NULL DEFAULT 32,
  src_ip text NOT NULL DEFAULT '', src_prefix_len int NOT NULL DEFAULT 0,
  protocol int NOT NULL DEFAULT 0,
  dst_port int NOT NULL DEFAULT 0, src_port int NOT NULL DEFAULT 0,
  action text NOT NULL CHECK (action IN ('pass','drop','rate_limit','challenge','syn_cookie')),
  rate_limit_pps bigint NOT NULL DEFAULT 0,
  priority int NOT NULL DEFAULT 50 CHECK (priority BETWEEN 1 AND 254),
  expires_unix bigint
);
```

Repo per the DAO pattern; cap of 100 active rules enforced at insert.

**API** (writes admin-gated via `requireAdminForWrites()`):
`GET /api/inline/rules`, `POST /api/inline/rules` (validate IPs, action enum,
rate > 0 when `rate_limit`, `expires_unix` in the future or null), `DELETE
/api/inline/rules/:id`. Each write publishes an audit-log entry
(`inline_manual_rule_create` / `inline_manual_rule_delete`).

**Engine.** `InlineMitigator` gains a manual rule source:
`snapshotRulesLocked` appends manual rules (converted with stable rule IDs in
the 1,000,000+ namespace to avoid collision with engine-generated IDs,
`attack_id = 0`, `reason = "manual"`, expired rows skipped at snapshot time).
Manual rules survive attack withdraws; any manual change bumps the snapshot
version and pushes to all connected nodes. Reconcile paths include them.

**Console.** "Manual rules" card on the Inline page: table (target, action,
rate, priority, expiry, created_by, note) + admin create form + delete with
XConfirm.

## E. `default_action` catch-all

Config `action_engine.default_action`: `""` (default, preserve), `"pass"`,
`"drop"`. When `"drop"`, every snapshot (including withdraw/empty ones) gains a
priority-255 all-zero DROP catch-all rule; `"pass"` and `""` emit no catch-all.
The node's tri-state semantics are already implemented. Tests pin: catch-all
present iff configured; withdraw preserves it; version semantics unchanged.

## D. Inline config push

**API.** `GET/PUT /api/nodes/:id/inline-config` (admin writes): fields the
proto already carries — `xdp_mode`, `af_xdp_queue`, `af_xdp_zero_copy`,
`cpu_pins[]`. Stored in a `node_inline_config` table (node_id PK).

**Push.** Dedicated `SendPostureConfig` mirroring `SendInlineRulePush`
(ConfigPush with `WatchConfig.posture` set) — deliberately not through
`configpub.cloneWatchConfig`, which strips unknown fields. Sent on PUT and on
node attach (after the rule snapshot). The node's `applyPostureConfig` applies
idempotently.

**Console.** Per-node "Inline config" editor (admin) in the node drawer.

**Stretch (proto regen required):** add `burst_pps` (field 7) and
`dns_protect` (field 8) to `NodePostureConfig` and handle them in
`applyPostureConfig`. Only if protoc tooling is available; otherwise those two
knobs stay node-YAML-only (documented).

## F. Hygiene

- demo/data.ts + demo/server.ts + mock/data.ts: fixtures for posture,
  mitigations, manual rules, history; demo-gates GET count updated.
- docs/INLINE.md §6: new endpoints table rows (history, manual rules,
  inline-config).
- i18n en/ar labels for all new UI strings.
- parity.test.ts: cover Inline.vue once the mocks carry the write endpoints.

---

## Testing

- **Store:** migration idempotency, repo CRUD, cap enforcement.
- **Ingestion:** PostureWriter window/flush behavior (last-sample-wins).
- **API:** admin gating, validation errors, `available:false` posture shape.
- **Engine:** manual-rule merge + version bump, withdraw keeps manual rules,
  expired-rule skip, catch-all tri-state, ID-namespace separation.
- **Node:** existing guards unchanged; `applyPostureConfig` tests already in
  place.
- **Console:** vitest for chart wiring, drawer section, manual-rules form;
  demo-gates count bump.

## Build order

A → B → C → E → D → F. Each unit lands as its own branch off main with green
Go + console suites before merge.

## Risks

- Protobuf regeneration availability for the D stretch — detected at D start;
  fallback documented.
- TimescaleDB absence — same guarded path as `ts_stats`.
- Snapshot growth from manual rules — capped at 100 active rules.
- Rule-ID collisions between engine and manual rules — separate namespaces.
