import { describe, expect, it } from 'vitest'
import { byKind, isRunning, shortImage, stateTone } from './logic'

describe('workloads logic', () => {
  it('maps states to tones and running', () => {
    expect(stateTone('running')).toBe('ok')
    expect(stateTone('paused')).toBe('warn')
    expect(stateTone('exited')).toBe('neutral')
    expect(stateTone('shut off')).toBe('neutral')
    expect(isRunning('frozen')).toBe(true)
    expect(isRunning('stopped')).toBe(false)
  })
  it('groups by kind in tool order', () => {
    const g = byKind(
      [
        { kind: 'qm', id: '200' },
        { kind: 'docker', id: 'a' },
        { kind: 'docker', id: 'b' },
      ],
      ['docker', 'qm', 'pct'],
    )
    expect(g.map(([k, l]) => [k, l.length])).toEqual([
      ['docker', 2],
      ['qm', 1],
      ['pct', 0],
    ])
  })
  it('shortens image references', () => {
    expect(shortImage('ghcr.io/paperless-ngx/paperless-ngx:2.13')).toBe('paperless-ngx:2.13')
    expect(shortImage('redis:7')).toBe('redis:7')
    expect(shortImage('debian')).toBe('debian')
  })
})
