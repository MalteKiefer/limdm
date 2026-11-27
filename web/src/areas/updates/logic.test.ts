import { describe, expect, it } from 'vitest'
import type { Pending, Ring } from './api'
import { approvable, previous, sortPending, splitList } from './logic'

const ring = (id: number, wave: number, extra: Partial<Ring> = {}): Ring =>
  ({
    id,
    tenant_id: 1,
    name: `r${id}`,
    position: id,
    wave,
    approved_wave: 0,
    ...extra,
  }) as Ring

describe('updates logic', () => {
  it('finds the ring before and whether approval helps', () => {
    const rings = [ring(1, 3), ring(2, 1, { require_approval: true, approved_wave: 1 }), ring(3, 0, { tenant_id: 2 })]
    expect(previous(rings, rings[1])?.id).toBe(1)
    expect(previous(rings, rings[2])).toBeUndefined()
    expect(approvable(rings, rings[1])).toBe(true)
    expect(approvable(rings, { ...rings[1], approved_wave: 3 })).toBe(false)
    expect(approvable(rings, rings[0])).toBe(false)
  })
  it('sorts security updates first', () => {
    const list = [{ name: 'vim' }, { name: 'curl', security: true, severity: 'Moderate' }, { name: 'openssl', security: true, severity: 'Important' }] as Pending[]
    expect(sortPending(list).map((p) => p.name)).toEqual(['openssl', 'curl', 'vim'])
  })
  it('splits lists', () => {
    expect(splitList(' a, b,,a ')).toEqual(['a', 'b'])
  })
})
