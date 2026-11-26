import { describe, expect, it } from 'vitest'
import { decodePreset, encodePreset, presetHref } from './preset'

describe('report presets', () => {
  it('round trips and keeps only the parameters of the kind', () => {
    const s = encodePreset({ kind: 'audit.csv', days: 30, actor: 'anna', at: '2026-01-01' })
    expect(s).toBe('kind=audit.csv&days=30&actor=anna')
    expect(decodePreset(s)).toEqual({ kind: 'audit.csv', days: 30, actor: 'anna' })
    expect(decodePreset('kind=secrets.csv')).toBeNull()
    expect(decodePreset('kind=audit.csv&days=-4')).toEqual({ kind: 'audit.csv' })
  })

  it('resolves relative days into a from date', () => {
    expect(presetHref({ kind: 'audit.jsonl', days: 7, q: 'ssh' }, new Date(2026, 0, 10))).toBe('/api/v1/exports/audit.jsonl?from=2026-01-03&q=ssh')
    expect(presetHref({ kind: 'compliance-history.csv', at: '2026-01-02', device: 'd1' })).toBe('/api/v1/exports/compliance-history.csv?at=2026-01-02&device=d1')
    expect(presetHref({ kind: 'inventory.csv' })).toBe('/api/v1/exports/inventory.csv')
  })
})
