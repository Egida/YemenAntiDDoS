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

  it('sums per-node deltas across nodes and maps every counter', () => {
    const rows: PostureRow[] = [
      row('2026-01-01T00:00:00Z', { emergency_drops: 100, syn_cookies_validated: 120, syn_cookies_dropped: 30 }),
      row('2026-01-01T00:01:00Z', { emergency_drops: 220, syn_cookies_validated: 240, syn_cookies_dropped: 60 }),
      row('2026-01-01T00:00:00Z', { node_id: 'edge-b', emergency_drops: 60, syn_cookies_validated: 0, syn_cookies_dropped: 0, af_xdp_umem_drops: 12 }),
      row('2026-01-01T00:01:00Z', { node_id: 'edge-b', emergency_drops: 0, syn_cookies_validated: 60, syn_cookies_dropped: 0, af_xdp_umem_drops: 72 }), // edge-b restarted
    ]
    const all = posturePoints(rows, '')
    expect(all).toHaveLength(2)
    expect(all[1].values.emergency).toBeCloseTo((120 + 0) / 60)   // edge-a +120; edge-b reset→0 must not hide it
    expect(all[1].values.cookies_ok).toBeCloseTo((120 + 60) / 60)
    expect(all[1].values.cookies_drop).toBeCloseTo((30 + 0) / 60)
    expect(all[1].values.umem).toBeCloseTo((0 + 60) / 60)         // edge-b 12→72; edge-a stays 0
    const onlyB = posturePoints(rows, 'edge-b')
    expect(onlyB).toHaveLength(2)
    expect(onlyB[1].values.emergency).toBe(0)
    expect(onlyB[1].values.umem).toBeCloseTo(60 / 60)
  })
})
