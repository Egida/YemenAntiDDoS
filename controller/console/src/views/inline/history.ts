// Inline posture history: normalization for the Inline page chart.
// Counters are cumulative; the chart wants per-second event rates. Deltas are
// computed per node first — so one node's counter restart (clamped to 0) can
// never hide its peers' events — then summed across nodes into per-timestamp
// buckets.
import type { Point } from '../../components/chart/math'

export type { Point }

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

const COUNTERS = ['emergency', 'cookies_ok', 'cookies_drop', 'umem'] as const

function counterValue(r: PostureRow): Record<string, number> {
  return {
    emergency: r.emergency_drops,
    cookies_ok: r.syn_cookies_validated,
    cookies_drop: r.syn_cookies_dropped,
    umem: r.af_xdp_umem_drops,
  }
}

// Sum a node's rows per timestamp (same-timestamp samples coalesce), then walk
// timestamps oldest→newest turning cumulative counters into per-second deltas.
// First bucket is 0; a counter going backwards (node restart) clamps to 0.
function nodeDeltaPoints(rows: PostureRow[]): Point[] {
  const byTime = new Map<number, Record<string, number>>()
  for (const r of rows) {
    const t = Date.parse(r.time)
    if (Number.isNaN(t)) continue
    const vals = counterValue(r)
    const acc = byTime.get(t)
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

// posturePoints converts raw history rows into XChart points. nodeFilter ''
// sums all nodes per bucket; a node id restricts to that node.
export function posturePoints(rows: PostureRow[], nodeFilter: string): Point[] {
  const filtered = nodeFilter ? rows.filter(r => r.node_id === nodeFilter) : rows
  if (!filtered.length) return []
  const byNode = new Map<string, PostureRow[]>()
  for (const r of filtered) {
    const list = byNode.get(r.node_id)
    if (list) list.push(r)
    else byNode.set(r.node_id, [r])
  }
  const merged = new Map<number, Record<string, number>>()
  for (const nodeRows of byNode.values()) {
    for (const p of nodeDeltaPoints(nodeRows)) {
      const acc = merged.get(p.time)
      if (!acc) { merged.set(p.time, { ...p.values }); continue }
      for (const k of COUNTERS) acc[k] = (acc[k] ?? 0) + (p.values[k] ?? 0)
    }
  }
  return [...merged.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([time, values]) => ({ time, values }))
}
