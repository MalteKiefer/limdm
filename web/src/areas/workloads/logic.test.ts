import { describe, expect, it } from 'vitest'
import { byKind, isRunning, outcome, pollDelay, resultError, resultState, shortImage, stateTone, WAIT_LIMIT } from './logic'

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
  it('polls a waiting command with backoff and stops after the limit', () => {
    expect([0, 9_999, 10_000, 30_000, 60_000, WAIT_LIMIT - 1].map(pollDelay)).toEqual([2000, 2000, 3000, 5000, 10_000, 10_000])
    expect(pollDelay(WAIT_LIMIT)).toBe(false)
  })
  it('tells the outcome of a sent command', () => {
    expect(outcome('pending', 1000)).toBe('wait')
    expect(outcome('sent', 1000)).toBe('wait')
    expect(outcome('sent', WAIT_LIMIT)).toBe('timeout')
    expect(outcome('ok', WAIT_LIMIT)).toBe('ok')
    expect(outcome('failed', 0)).toBe('failed')
    expect(outcome('expired', 0)).toBe('failed')
    expect(outcome(undefined, 0)).toBe('wait')
  })
  it('reads the state and error of a result', () => {
    expect(resultState('stop docker web\nweb\nstate: exited')).toBe('exited')
    expect(resultState('state: running (not yet stopped after 30s)')).toBe('running (not yet stopped after 30s)')
    expect(resultState('ok')).toBe('')
    expect(resultError('\nworkload control is not allowed')).toBe('workload control is not allowed')
  })
})
