import { describe, expect, it } from 'vitest'
import { badNet, badTime, cleanSchedule, colorCheck, isNet, isPEM, isSyslog, keepEmpty, lines, parseRoleGroups, roleGroupsText } from './logic'

describe('settings logic', () => {
  it('splits lists', () => {
    expect(lines(' 10.0.0.0/8\n2001:db8::/32,  1.2.3.4 ')).toEqual(['10.0.0.0/8', '2001:db8::/32', '1.2.3.4'])
  })
  it('checks networks', () => {
    for (const ok of ['10.0.0.0/8', '1.2.3.4', '2001:db8::/32', '::1', 'fe80::1/64']) expect(isNet(ok), ok).toBe(true)
    for (const bad of ['10.0.0.0/33', '300.1.1.1', 'example.com', '1.2.3.4/', '2001:db8::/129', '1::2::3', '1.2.3.4/8/9']) expect(isNet(bad), bad).toBe(false)
    expect(badNet('10.0.0.0/8 nope')).toBe('nope')
  })
  it('reads role groups like the server', () => {
    const r = parseRoleGroups('it-admins; admin\nsupport; helpdesk; berlin, munich\n')
    expect(r.error).toBeUndefined()
    expect(r.groups).toEqual([{ group: 'it-admins', role: 'admin' }, { group: 'support', role: 'helpdesk', tags: ['berlin', 'munich'] }])
    expect(roleGroupsText(r.groups)).toBe('it-admins; admin\nsupport; helpdesk; berlin,munich')
    expect(parseRoleGroups('x; owner').error).toBe('x; owner')
  })
  it('checks syslog, PEM and times', () => {
    expect(isSyslog('tcp+tls://siem.example.com:6514')).toBe(true)
    expect(isSyslog('https://siem')).toBe(false)
    expect(isPEM('-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----')).toBe(true)
    expect(isPEM('garbage')).toBe(false)
    expect(badTime('02:00, 14:30')).toBeUndefined()
    expect(badTime('2:00 25:00')).toBe('2:00')
  })
  it('guards brand colors', () => {
    expect(colorCheck('#ffff00')?.ok).toBe(false)
    expect(colorCheck('#0f6e6e')?.text).toBe(true)
    expect(colorCheck('teal')).toBeNull()
  })
  it('sends only the fields of a schedule kind', () => {
    const s = cleanSchedule({ name: 'n', kind: 'monthly', day: 1, times: ['02:00'], days: [1], every: 4, targets: ['disk'], keep: { monthly: 12 } })
    expect(s).toEqual({ name: 'n', paused: undefined, kind: 'monthly', day: 1, times: ['02:00'], targets: ['disk'], keep: { monthly: 12 } })
    expect(keepEmpty({ daily: 0 })).toBe(true)
  })
})
