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
