import { describe, expect, it } from 'vitest'
import { agentShare, marksByDay } from './marks'

describe('home helpers', () => {
  it('joins annotations per day inside the history', () => {
    const m = marksByDay(
      [
        { day: '2026-01-02', action: 'blueprint.save', label: 'Blueprint saved', target: 'x', count: 2 },
        { day: '2026-01-02', action: 'keys.rotate', label: 'Keys rotated', target: '', count: 1 },
        { day: '2025-12-01', action: 'keys.rotate', label: 'Keys rotated', target: '', count: 1 },
      ],
      ['2026-01-01', '2026-01-02'],
    )
    expect([...m]).toEqual([['2026-01-02', 'Blueprint saved (2), Keys rotated']])
  })

  it('computes the agent share', () => {
    expect(agentShare(3, 4)).toBe(75)
    expect(agentShare(0, 0)).toBeUndefined()
  })
})
