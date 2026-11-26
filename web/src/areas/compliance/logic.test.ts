import { describe, expect, it } from 'vitest'
import { activeFor, checkException, countStates, filterChecks, heatMatrix, isoDay, passRate, sha256Hex, sortChecks, type Check, type Exception } from './logic'

const mk = (id: string, pass: number, fail: number, extra: Partial<Check> = {}): Check => ({ id, title: id, level: 1, refs: {}, pass, fail, na: 0, excepted: 0, failing_hosts: [], ...extra })
const checks = [mk('ssh.baseline', 8, 2, { refs: { bsi: ['SYS.2.3'] } }), mk('net.tcp', 10, 0, { level: 2 }), mk('custom.x', 0, 0), mk('kernel.aslr', 5, 5)]

describe('checks', () => {
  it('filters by state, level, framework and text', () => {
    expect(filterChecks(checks, { state: 'failing' }).map((c) => c.id)).toEqual(['ssh.baseline', 'kernel.aslr'])
    expect(filterChecks(checks, { state: 'passing' }).map((c) => c.id)).toEqual(['net.tcp'])
    expect(filterChecks(checks, { level: '2' }).map((c) => c.id)).toEqual(['net.tcp'])
    expect(filterChecks(checks, { fw: 'bsi' }).map((c) => c.id)).toEqual(['ssh.baseline'])
    expect(filterChecks(checks, { q: 'ASLR' }).map((c) => c.id)).toEqual(['kernel.aslr'])
  })
  it('sorts most failing first by default, ties by id', () => {
    expect(sortChecks(checks).map((c) => c.id)).toEqual(['kernel.aslr', 'ssh.baseline', 'custom.x', 'net.tcp'])
    expect(sortChecks(checks, 'rate').map((c) => c.id)[0]).toBe('kernel.aslr')
    expect(sortChecks(checks, 'rate').at(-1)!.id).toBe('custom.x') // no results last
  })
  it('computes the pass rate', () => {
    expect(passRate({ pass: 3, fail: 1 })).toBe(75)
    expect(passRate({ pass: 0, fail: 0 })).toBeNull()
  })
})

describe('heatmap', () => {
  it('builds rows, columns and rates', () => {
    const m = heatMatrix([
      { column: 'lab', area: 'ssh', pass: 1, fail: 1 },
      { column: 'default', area: 'ssh', pass: 4, fail: 0 },
      { column: 'lab', area: 'kernel', pass: 0, fail: 2 },
    ])
    expect(m.areas).toEqual(['kernel', 'ssh'])
    expect(m.columns).toEqual(['default', 'lab'])
    expect(m.rate).toEqual([[null, 0], [100, 50]])
  })
})

describe('exceptions', () => {
  const today = new Date(2026, 10, 26)
  const ok = { check_id: 'net.forwarding', mode: 'exclude', tag: '', reason: 'lab', owner: 'cto', approver: 'ciso@firma.de', expires: '2027-01-31' }
  it('accepts a valid draft', () => {
    expect(checkException(ok, { fourEyes: true, login: 'admin@firma.de', today })).toEqual({})
  })
  it('enforces four eyes, expiry window, tag and check id', () => {
    expect(checkException({ ...ok, approver: 'Admin@firma.de' }, { fourEyes: true, login: 'admin@firma.de', today }).approver).toBe('self')
    expect(checkException({ ...ok, approver: 'admin@firma.de' }, { fourEyes: false, login: 'admin@firma.de', today })).toEqual({})
    expect(checkException({ ...ok, expires: '2026-11-25' }, { fourEyes: false, login: 'x', today }).expires).toBe('expires')
    expect(checkException({ ...ok, expires: '2026-11-26' }, { fourEyes: false, login: 'x', today })).toEqual({})
    expect(checkException({ ...ok, expires: '2029-11-27' }, { fourEyes: false, login: 'x', today }).expires).toBe('expires')
    expect(checkException({ ...ok, tag: 'a,b' }, { fourEyes: false, login: 'x', today }).tag).toBe('tag')
    expect(checkException({ ...ok, check_id: 'bad id' }, { fourEyes: false, login: 'x', today }).check_id).toBe('check')
    expect(checkException({ ...ok, reason: ' ' }, { fourEyes: false, login: 'x', today }).reason).toBe('reason')
  })
  it('counts states and finds active ones per check', () => {
    const list = [
      { id: 1, check_id: 'a', state: 'active' },
      { id: 2, check_id: 'a', state: 'revoked' },
      { id: 3, check_id: 'b', state: 'expired' },
    ] as Exception[]
    expect(countStates(list)).toEqual({ active: 1, expired: 1, revoked: 1, all: 3 })
    expect(activeFor(list, 'a').map((e) => e.id)).toEqual([1])
  })
})

describe('helpers', () => {
  it('formats a local day', () => expect(isoDay(new Date(2026, 0, 5))).toBe('2026-01-05'))
  it('hashes like sha256sum', async () => {
    expect(await sha256Hex(new TextEncoder().encode('abc').buffer)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})
