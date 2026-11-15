# BGP Flowspec & RTBH

> العربية: [docs/FLOWSPEC.ar.md](FLOWSPEC.ar.md)

## Overview

The controller embeds a [GoBGP](https://github.com/osrg/gobgp) speaker and originates mitigation routes over real BGP sessions:

- **Flowspec** (RFC 8955) — per-flow drop or rate-limit rules.
- **RTBH** (RFC 7999) — host blackholes signalled with the well-known blackhole next-hop.

There is no local FRR and no vendor CLI rendering. Every configured, established neighbor receives the same active rules (the same propagation model the previous FRR-based setup provided).

## Setup

Configuration is done in the Web Console (nothing BGP-related lives in `config.yaml`).

1. **Settings → BGP Instance** — the speaker identity, shared by all neighbors:
   - `local_asn` — the controller's autonomous system number.
   - `router_id` — IPv4 router-id for the speaker.
   - `listen_port` — BGP listen port (default `179`; set `0` for active-connect-only deployments).
   - `rtbh_next_hop` — next-hop used for RTBH blackhole routes (e.g. a blackhole community next-hop).
2. **Settings → BGP Connectors** — one connector per upstream router/neighbor:
   - `name`, `bgp_asn` (local ASN context), `neighbor_ip`, `neighbor_asn`.
   - `md5_password` (optional) — TCP MD5 authentication shared with the neighbor.
   - `address_family` — `auto` by default.
   - `flowspec_enabled` — announce Flowspec rules on this neighbor; when off, mitigations fall back to RTBH for that connector.
   - `enabled` — disable to tear down the session.

## Mitigation flow

1. An attack triggers a BGP action bound to a connector.
2. The controller builds a refcounted `bgp_announcement` and adds the encoded path to the embedded speaker (`AddPath`). The announcement records are stored with `kind`/`rule_spec` (the flowspec rule JSON) for RTBH and flowspec rules.
3. The path is advertised to all established peers. Multiple attacks/holders share a single announcement via refcounting.
4. On expiry (including delayed-withdraw timers) the refcount drops; when it reaches zero the path is withdrawn (`DeletePath`). Refcounted withdrawals are idempotent.
5. Disabling or deleting a connector retires its neighbor session; the neighbor withdraws routes learned from us (equivalent to a session teardown).
6. On controller restart the RIB is memory-only and rebuilt from persisted announcements in the database.

## Console

- **Mitigations → Flowspec** lists active announcements with the rule match tuple and status, and supports force-withdraw of a single announcement.
- The announcement drawer shows the **match** tuple and the **rule JSON** (speaker-native), plus attached attacks.
- The **Preview** panel renders the match tuple and rule JSON for a given prefix/protocol/port/action without creating an announcement.

## Metrics

| Metric | Description |
|---|---|
| `xsight_bgp_peer_up{connector,neighbor}` | 1 when the session to `neighbor` is established, 0 otherwise. |
| `xsight_bgp_paths{kind}` | Number of paths currently originated, by `kind` (`rtbh` / `flowspec`). |
| `xsight_bgp_speaker_errors_total{op}` | Speaker operation errors (`add_path`, `delete_path`, `sync`, ...). |

The legacy `xsight_vtysh_ops_total` metric has been removed.

## Limitations

- **All peers receive all rules.** The embedded speaker advertises every active announcement to every established neighbor, matching the propagation behavior of the previous single-routing-instance FRR model. Per-peer export filtering/policy is a fast-follow.
