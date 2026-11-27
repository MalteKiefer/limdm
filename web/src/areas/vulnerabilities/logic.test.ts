import { describe, expect, it } from 'vitest'
import { checkAccept, cleared, filtered, remediatedPct, sevLevel, toQuery } from './logic'

describe('vulnerabilities logic', () => {
  it('maps the URL to the API query with active as the default status', () => {
    expect(toQuery({})).toMatchObject({
      status: 'active',
      sort: '-severity',
      kev: undefined,
    })
    expect(
      toQuery({
        q: ' ssl ',
        sev: 'critical,high',
        status: 'all',
        pkg: 'openssl',
        kev: 'on',
        sort: 'cvss',
      }),
    ).toMatchObject({
      q: 'ssl',
      severity: 'critical,high',
      status: 'all',
      package: 'openssl',
      kev: 'true',
      sort: 'cvss',
    })
  })
  it('knows a filtered view and clears it', () => {
    expect(filtered({ status: 'active', sort: 'cvss' })).toBe(false)
    expect(filtered({ status: 'remediated' })).toBe(true)
    expect(cleared({ q: 'x', os: 'debian', sort: 'cvss', sel: 'CVE-2024-1' })).toEqual({ sort: 'cvss', sel: 'CVE-2024-1', full: undefined })
  })
  it('levels and shares', () => {
    expect([sevLevel('critical'), sevLevel('low'), sevLevel('unknown'), sevLevel(undefined)]).toEqual([4, 1, 0, 0])
    expect(remediatedPct({ active: 1, accepted: 1, remediated: 2 })).toBe(50)
    expect(remediatedPct({})).toBe(0)
  })
  it('checks an acceptance like the server', () => {
    const now = new Date(2026, 10, 27)
    expect(checkAccept({ reason: 'lab', expires: '2026-12-31', device_id: '', package: '' }, now)).toEqual({})
    expect(checkAccept({ reason: ' ', expires: '2028-01-01', device_id: '', package: '' }, now)).toEqual({ reason: true, expires: true })
    expect(checkAccept({ reason: 'x', expires: '2026-11-26', device_id: '', package: '' }, now)).toEqual({ expires: true })
  })
})
