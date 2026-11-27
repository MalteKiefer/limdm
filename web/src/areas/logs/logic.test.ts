import { describe, expect, it } from 'vitest'
import { apiParams, buildQuery, groupCounts, prioGroup, prioTone, tailDelay, timeRange, zoomTo } from './logic'

describe('logs logic', () => {
  it('builds the query from the filter fields', () => {
    expect(buildQuery({ q: ' "connection refused" ', source: 'container', prio: 'err', device: 'mail host' })).toBe('"connection refused" source:container prio<=err device:"mail host"')
    expect(buildQuery({ source: 'bogus', prio: 'loud' })).toBe('')
  })

  it('uses quick ranges that end at the next minute', () => {
    const now = Date.UTC(2026, 0, 1, 10, 30, 20)
    expect(timeRange({ range: '15m' }, now)).toEqual({ from: '2026-01-01T10:16:00.000Z', to: '2026-01-01T10:31:00.000Z' })
    expect(timeRange({}, now).from).toBe('2026-01-01T09:31:00.000Z')
    const custom = timeRange({ range: 'custom', from: '2026-01-01T08:00', to: '2026-01-01T09:00' }, now)
    expect(new Date(custom.to).getTime() - new Date(custom.from).getTime()).toBe(3_600_000)
    // a broken custom range falls back to one hour
    expect(timeRange({ range: 'custom', from: 'x' }, now).from).toBe('2026-01-01T09:31:00.000Z')
  })

  it('fixes the device on the device tab', () => {
    const p = apiParams({ device: 'other', q: 'x' }, 'd1', Date.UTC(2026, 0, 1))
    expect(p.device).toBe('d1')
    expect(p.q).toBe('x')
  })

  it('zooms into a bucket', () => {
    const z = zoomTo('2026-01-01T10:00:00Z', 300)
    expect(z.range).toBe('custom')
    expect(new Date(z.to!).getTime() - new Date(z.from!).getTime()).toBe(300_000)
  })

  it('groups priorities', () => {
    expect(prioGroup(0)).toBe('crit')
    expect(prioGroup(6)).toBe('info')
    expect(prioTone(3)).toBe('bad')
    expect(prioTone(7)).toBe('neutral')
    expect(groupCounts([1, 0, 1, 2, 3, 4, 5, 6])).toEqual({ crit: 2, err: 2, warning: 3, info: 9, debug: 6 })
  })

  it('backs the live tail off', () => {
    expect(tailDelay(0)).toBe(5000)
    expect(tailDelay(2)).toBe(20000)
    expect(tailDelay(9)).toBe(60000)
  })
})
