import { describe, expect, it } from 'vitest'
import { byRisk, isMuted, mute, nextAfter, risk, type InboxItem } from './risk'

describe('inbox risk', () => {
  it('rates the action types', () => {
    expect(risk({ action: 'command', payload: { type: 'wipe' } })).toBe(3)
    expect(risk({ action: 'command', payload: { type: 'script' } })).toBe(2)
    expect(risk({ action: 'remote_shell', payload: {} })).toBe(3)
    expect(risk({ action: 'token.add', payload: {} })).toBe(2)
    expect(risk({ action: 'library.save', payload: {} })).toBe(1)
  })

  it('sorts by risk, then expiry, then age', () => {
    const items: InboxItem[] = [
      { id: 'low', risk: 1, at: '2026-01-03' },
      { id: 'late', risk: 2, at: '2026-01-01', expires: '2026-01-05' },
      { id: 'soon', risk: 2, at: '2026-01-01', expires: '2026-01-02' },
      { id: 'high', risk: 3, at: '2026-01-01' },
    ]
    expect(items.sort(byRisk).map((x) => x.id)).toEqual(['high', 'soon', 'late', 'low'])
  })

  it('moves the selection to the next item', () => {
    const l = [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
    expect(nextAfter(l, 'b')).toBe('c')
    expect(nextAfter(l, 'c')).toBe('b')
    expect(nextAfter([{ id: 'a' }], 'a')).toBeUndefined()
  })

  it('mutes a warning for seven days', () => {
    mute('w-stale', true, 0)
    expect(isMuted('w-stale', 1)).toBe(true)
    expect(isMuted('w-stale', 8 * 86_400_000)).toBe(false)
    mute('w-stale', false, 1)
    expect(isMuted('w-stale', 1)).toBe(false)
  })
})
