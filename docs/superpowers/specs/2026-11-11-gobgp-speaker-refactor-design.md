# GoBGP Speaker Refactor — Flowspec & RTBH over native BGP (v5.0)

Status: approved design, 2026-11-11. Replaces the vtysh/FRR execution model for
BGP Flowspec and RTBH with an embedded GoBGP speaker (github.com/osrg/gobgp/v3,
pinned v3.37.0) so the Controller originates rules over real BGP sessions.

## Context

Today the Controller never speaks BGP. Both mitigation exports are rendered as
CLI and pushed into one local FRR box via `vtysh`:

1. **RTBH** (controller/internal/action/bgp.go): `network <prefix> route-map <rm>`
   announce/withdraw against the local FRR; outcome classified by scraping vtysh
   output (`isFRRRouteAbsentError`).
2. **Flowspec** (controller/internal/action/bgp_flowspec.go, .../flowspec/):
   vendor-neutral `flowspec.Rule` rendered to CLI per vendor. Only FRR is
   executed; Cisco XR / Juniper / Arista are export-only (commands shown in the
   console for manual application, announcement marked failed).

Consequences: no BGP session from the Controller to any router, so only a
co-located FRR can receive rules; export-only vendors are a copy-paste burden;
outcome detection depends on fragile stderr scraping; the controller image
ships FRR purely as a vtysh client.

## Decision: GoBGP, embedded

ExaBGP (Python daemon, stdin/stdout JSON API) and GoBGP (Go library, RFC 8955
flowspec) were compared. GoBGP wins for this codebase:

| Criterion | ExaBGP | GoBGP v3 |
|---|---|---|
| Runtime | Python subprocess, supervised lifecycle | Go library, in-process |
| Integration | JSON over stdio, parse stdout for errors | Direct Go API (`AddPath`/`DeletePath`) |
| Flowspec | Excellent | Full: IPv4/IPv6 NLRI (SAFI 133) + action ext-communities |
| RTBH | Yes | Yes (unicast origination + RFC 7999 blackhole community) |
| Deployment | Adds Python + IPC to a pure-Go image | No new runtime |
| Testing | Black-box | In-process two-speaker integration tests |

Approved scope decisions (2026-11-11):

1. **Scope**: Flowspec **and** RTBH move to the speaker; the vtysh path is fully
   retired.
2. **Integration**: embedded `gobgp.Server` in the controller binary (not a
   gobgpd sidecar, not ExaBGP).
3. **Peer config**: `bgp_connectors` rows become neighbor definitions
   (console-managed, as today). New single-row `bgp_instance` holds global
   identity.
4. **Vendor CLI rendering**: removed entirely (no export-only mode, no manual
   command drawer); `vendor` becomes informational; FRR/vtysh leaves the image.

## Architecture

### New package `controller/internal/bgp`

Wraps one `gobgp.Server` behind an interface so the action engine stays
testable with a fake:

```go
type Speaker interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    // Flowspec: encode rule -> flowspec NLRI + traffic-rate ext-community.
    AnnounceFlowspec(ctx context.Context, rule flowspec.Rule) error
    WithdrawFlowspec(ctx context.Context, rule flowspec.Rule) error
    // RTBH: unicast origination + well-known blackhole community.
    AnnounceBlackhole(ctx context.Context, prefix string) error
    WithdrawBlackhole(ctx context.Context, prefix string) error
    // Reconcile connector rows -> gobgp neighbors (add/update/delete).
    SyncPeers(ctx context.Context, peers []Peer) error
    PeerStates(ctx context.Context) []PeerState
}
```

The speaker keeps an in-memory map `pathKey -> gobgp path uuid` so withdraws
delete exactly the path added (same NLRI announced twice must not duplicate).
Keys derive deterministically from the rule (family + NLRI components), so
recovery after restart cannot orphan or duplicate entries (the RIB is empty
after a restart).

`flowspec.Rule` (controller/internal/action/flowspec/flowspec.go) stays as the
vendor-neutral rule type — it already matches RFC 8955 components 1:1:

| Rule field | RFC 8955 component |
|---|---|
| `Prefix` | Type 1 Destination Prefix |
| `Protocol` | Type 3 IP Protocol |
| `DstPort` | Type 5 Destination Port |
| `SrcPort` | Type 6 Source Port |
| `Action` drop | ext-community `traffic-rate-bytes` (0x8006) rate 0 |
| `Action` rate-limit | 0x8006 with IEEE 754 float, **bytes per second** (RFC 8955 §7.1) |

Deleted: `Render`, `RenderWithdraw`, all vendor templates, `templateFor`,
`substitute`, `protoName` CLI dialects, `ParseVendor` (with it: the
export-only branches, `runVtysh`, `vtyshTokens`, `isFRRRouteAbsentError`,
`metrics.RecordVtysh`). The `flowspec` package shrinks to the `Rule` type +
validation + JSON (de)serialization used by `rule_spec`.

### Peering model

- **One speaker, all peers** — a path added to the global RIB advertises to
  every established flowspec-capable (and unicast-capable, for RTBH) peer.
  This matches today's semantics exactly: the old single local FRR also
  propagated every rule to all of its neighbors.
- **`bgp_instance`** (new single-row table, console-managed):
  `local_asn INT NOT NULL`, `router_id TEXT NOT NULL` (IPv4 dotted quad),
  `listen_port INT NOT NULL DEFAULT 179`, `rtbh_next_hop TEXT NOT NULL DEFAULT ''`
  (empty = use `router_id` as next-hop for RTBH origination). Changes require
  speaker restart (Stop → Start → recover paths).
- **`bgp_connectors`** gains `neighbor_ip TEXT NOT NULL DEFAULT ''`,
  `neighbor_asn INT NOT NULL DEFAULT 0`, `md5_password TEXT NOT NULL DEFAULT ''`.
  Existing fields keep their roles: `bgp_asn` (validated == `local_asn`),
  `enabled`,   `address_family` (`ipv4`/`ipv6` selects the AFI for that peer's
  unicast + flowspec families; legacy `auto` derives it from `neighbor_ip`),
  `flowspec_enabled` (flowspec vs RTBH actions),
  `vendor` informational. Validation on create/update: an **enabled** connector
  requires non-empty `neighbor_ip`, positive `neighbor_asn`, and `bgp_asn`
  equal to the instance's `local_asn`. Disabling a connector deletes the gobgp
  peer → session teardown → that neighbor auto-withdraws everything learned
  from the speaker.

### Data flow

**Flowspec announce** — unchanged refcount machinery; only the final executor
changes: attack → `executeBGPFlowspec` → `flowspecRuleFor` → DB `Attach` → if
`NeedAnnounce` → `speaker.AnnounceFlowspec(rule)` → `AddPath` (flowspec NLRI +
ext-communities) → `MarkAnnounced`. `rule_spec` JSON in `bgp_announcements`
continues to be the durable record (rule name, matches, action).

**RTBH** — `bgpAnnounce` → `Attach` → if `NeedAnnounce` →
`speaker.AnnounceBlackhole(prefix)` → unicast path with next-hop
`rtbh_next_hop` (default `router_id`) + community 65535:666 (RFC 7999
BLACKHOLE). `route_map` stays as announcement identity only; nothing renders it.

**Withdraw** — DB `Detach` → if `NeedWithdraw` → `speaker.WithdrawFlowspec` /
`WithdrawBlackhole` → `DeletePath` → `MarkWithdrawn`. The delayed-withdraw
machinery (PR-5 timers, `bgpDelayedWithdrawWorker`, generation guards,
`MarkWithdrawing`) is untouched — `performBGPWithdraw` swaps its vtysh call for
the speaker call. Withdraw of a missing path is a gobgp no-op → the old
`isFRRRouteAbsentError` idempotency scraping disappears.

**Force withdraw** (`POST /api/flowspec/announcements/:id/withdraw`) —
`speaker.WithdrawFlowspec` + `MarkWithdrawn` + delay cancel, minus vtysh.

**Recovery** — `RecoverBGPRoutes` becomes speaker recovery: re-read
`active`/`delayed` announcements, re-encode flowspec rules from `rule_spec`
(RTBH from `prefix`), `AddPath` each. Runs after `speaker.Start`; BGP sessions
re-establish automatically.

## Error handling

- **`AddPath`/`DeletePath` error** → same compensation as today:
  `MarkFailedAnnounce`/`MarkFailedWithdraw` within the original generation,
  `retryBGPStateWrite` + `ErrStaleAnnouncement` guards unchanged.
- **Peer session down** → paths remain in the RIB; gobgp re-advertises on
  session re-establishment (no per-path action, unlike vtysh where a failed
  push meant the rule never existed). Session state surfaces in metrics/console.
- **Speaker not started** (no `bgp_instance` row yet) → announce fails closed
  with a clear error message; announcements compensate as failed.
- **Connector validation** moves from vendor checks (`vendor != frr &&
  !flowspec_enabled` rejection) to peer checks above. Existing
  `TestBgpVendorCreate/Update` tests are replaced by peer-validation tests.
- **Unknown/old rows**: rows with empty `neighbor_ip` fail closed until
  configured — identical philosophy to today's export-only failure.

## Metrics

Removed: `xsight_vtysh_total`/related (`RecordVtysh`). Added:

- `xsight_bgp_peer_up{connector=...}` — gauge 0/1 per peer
- `xsight_bgp_paths{kind=rtbh|flowspec}` — gauge of paths in the speaker RIB
- `xsight_bgp_speaker_errors` — counter of `AddPath`/`DeletePath`/`SyncPeers`
  failures

## API & console

- `GET/PUT /api/bgp/instance` — global identity (local_asn, router_id,
  listen_port, rtbh_next_hop).
- `GET /api/bgp/peers` — per-connector session state (up/down, uptime,
  established counts) for the connectors page.
- Connector create/update payloads gain `neighbor_ip`, `neighbor_asn`,
  `md5_password`; vendor validation removed.
- `POST /api/flowspec/preview` returns the rule JSON plus a human-readable
  match tuple (`destination 198.51.100.7/32, protocol tcp, destination-port 80,
  action traffic-rate 0`) instead of vendor CLI. Vendor list endpoint dropped.
- Console (controller/console/src): `views/connectors/` form fields (neighbor
  IP/ASN/MD5, remove vendor/vtysh), `views/mitigations/Flowspec.vue` drawer
  shows rule JSON + match tuple, `api/contract.ts` types, i18n en/ar strings,
  and the demo/mock fixtures (`console/demo`, `console/mock`) for the new
  endpoint shapes.

## Testing

- **Unit**: Rule → NLRI/ext-community encoding with golden byte sequences
  (drop, rate-limit, protocol, dst/src port combos, IPv4 + IPv6, RFC 8955 §4.3
  examples as fixtures); RTBH path attributes (next-hop, blackhole community);
  peer reconciliation diffs; connector/instance validation.
- **Engine**: existing action tests swap vtysh fakes for a `Speaker` fake —
  refcount, delay, generation, skip-reason behavior tests keep their shape.
- **Integration** (skipped in `-short`): two in-process gobgp servers —
  controller speaker + fake upstream — assert the flowspec NLRI and blackhole
  path arrive with correct attributes.
- Environment note: build/test with `GOTOOLCHAIN=auto` (project pins go 1.25).

## Migration & deployment

- **DB** (added to the migration list in postgres.go, no data backfill):
  ```sql
  CREATE TABLE IF NOT EXISTS bgp_instance (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    local_asn INT NOT NULL DEFAULT 0,
    router_id TEXT NOT NULL DEFAULT '',
    listen_port INT NOT NULL DEFAULT 179,
    rtbh_next_hop TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ DEFAULT now()
  );
  ALTER TABLE bgp_connectors ADD COLUMN IF NOT EXISTS neighbor_ip TEXT NOT NULL DEFAULT '';
  ALTER TABLE bgp_connectors ADD COLUMN IF NOT EXISTS neighbor_asn INT NOT NULL DEFAULT 0;
  ALTER TABLE bgp_connectors ADD COLUMN IF NOT EXISTS md5_password TEXT NOT NULL DEFAULT '';
  ```
- **Dockerfile**: drop the `frr` package and the `frr,frrvty` group membership.
- **docker-compose.yml**: remove the `/run/frr` mount; expose BGP
  (`"179:179"`; note that active-connect-only deployments can omit it) and
  `cap_add: [NET_BIND_SERVICE]` for the sub-`1024` default port.
- **Docs**: rewrite docs/FLOWSPEC.md + FLOWSPEC.ar.md (peering model, instance
  config, no more vendor CLI), update ENTERPRISE-UPGRADE-AR.md flowspec section,
  config.example.yaml BGP comment block, CHANGELOG.md (+ zh).

## Out of scope (fast-follow candidates)

- Per-connector export filtering via gobgp policies (v1 = all peers get all
  rules, same as the old FRR propagation model).
- Graceful restart / graceful shutdown for zero-withdraw controller upgrades.
- Additional flowspec matches (ICMP type/code, TCP flags, packet length, DSCP,
  fragment) and actions (redirect, mark) — `Rule` stays minimal; the encoder
  only grows.
- Redirect-to-VRF scrubbing coordination with xDrop nodes.
