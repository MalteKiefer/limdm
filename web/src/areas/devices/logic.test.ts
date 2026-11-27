import { describe, expect, it } from 'vitest'
import { enrollConf, installCommand } from './enrolltext'
import { accountActionable, badParamLine, connectionState, filterByName, firewallHealth, formatAttrs, mayCommand, orderNotices, parseAttrs, parseTags, pkgValue, statusTone, suggestUsername, updatesHealth, usedPct, userError } from './logic'

describe('enrollment texts', () => {
  it('prints the install command and enroll.conf', () => {
    expect(installCommand('https://mdm.test', 'lmt_x')).toBe('curl -fsSL https://mdm.test/install.sh | sudo LIMDM_TOKEN=lmt_x sh')
    expect(installCommand('https://mdm.test')).toBe('curl -fsSL https://mdm.test/install.sh | sudo sh')
    expect(enrollConf('https://a:8444', 'ab:cd', 'lmt_x').split('\n')).toEqual(['server = "https://a:8444"', 'fingerprint = "ab:cd"', 'token = "lmt_x"', 'allow_scripts = false', 'allow_remote_shell = false'])
  })
})

describe('devices logic', () => {
  it('lets the helpdesk send only its commands', () => {
    expect(mayCommand('sync', { admin: false, commands: true })).toBe(true)
    expect(mayCommand('wipe', { admin: false, commands: true })).toBe(false)
    expect(mayCommand('script', { admin: false, commands: false })).toBe(false)
    expect(mayCommand('wipe', { admin: true, commands: true })).toBe(true)
  })

  it('checks desktop users like the server', () => {
    const u = (username: string, email = 'a@x.de') => ({ username, email, admin: false })
    expect(userError([u('jdoe')], 0)).toBeUndefined()
    expect(userError([u('root')], 0)).toBe('name')
    expect(userError([u('9x')], 0)).toBe('name')
    expect(userError([u('max', 'nomail')], 0)).toBe('email')
    expect(userError([u('a'), u('a', 'b@x.de')], 1)).toBe('dup')
    expect(suggestUsername('Jane.Doe-2@Example.com')).toBe('janedoe-2')
    expect(suggestUsername('42max@x.de')).toBe('max')
  })

  it('derives the health cards and the notice order', () => {
    expect(updatesHealth([])).toEqual({ tone: 'off', state: 'unknown' })
    expect(updatesHealth([{ id: 'updates.security', status: 'fail', detail: '3 pending' }, { id: 'updates.reboot', status: 'fail' }])).toEqual({ tone: 'bad', state: 'pending', detail: '3 pending' })
    expect(updatesHealth([{ id: 'updates.security', status: 'pass' }, { id: 'updates.reboot', status: 'fail' }]).state).toBe('reboot')
    expect(updatesHealth([{ id: 'updates.security', status: 'pass' }, { id: 'updates.auto', status: 'fail' }]).state).toBe('manual')
    expect(updatesHealth([{ id: 'updates.security', status: 'pass' }, { id: 'updates.auto', status: 'pass', detail: 'mode all' }])).toEqual({ tone: 'ok', state: 'current', detail: 'mode all' })
    expect(firewallHealth([{ id: 'firewall.active', status: 'fail' }], [{ type: 'com.limdm.firewall' }])).toEqual({ tone: 'bad', state: 'inactive', managed: true })
    expect(firewallHealth([], []).state).toBe('unknown')
    expect(connectionState(null, 'pending').state).toBe('never')
    expect(connectionState('2026-01-01T00:00:00Z', 'stale').tone).toBe('warn')
    expect(orderNotices([{ level: 'info' as const }, { level: 'compliance' as const }, { level: 'security' as const }]).map((n) => n.level)).toEqual(['security', 'compliance', 'info'])
  })

  it('parses template attributes', () => {
    expect(parseAttrs('site = ber\n\nnet=10.0.0.0/8')).toEqual({ attrs: { site: 'ber', net: '10.0.0.0/8' } })
    expect(parseAttrs('1x=y').error).toBe('1x=y')
    expect(parseAttrs('a=1\na=2').error).toBe('a=2')
    expect(formatAttrs({ a: '1', b: 'x=y' })).toBe('a=1\nb=x=y')
  })

  it('parses tags', () => {
    expect(parseTags('Prod, berlin,prod')).toEqual({ tags: ['prod', 'berlin'] })
    expect(parseTags('a b').error).toBe('a b')
  })

  it('checks script parameter lines', () => {
    expect(badParamLine('A=1\n\nB_2 = x')).toBeUndefined()
    expect(badParamLine('A=1\nnope')).toBe('nope')
  })

  it('keeps a package filter one term', () => {
    expect(pkgValue(' openssl < 3.0.13 ')).toBe('openssl<3.0.13')
  })

  it('filters, rates and computes', () => {
    expect(filterByName([{ name: 'openssl' }, { name: 'bash' }], 'SSL')).toEqual([{ name: 'openssl' }])
    expect(statusTone('ok')).toBe('ok')
    expect(statusTone('failed')).toBe('bad')
    expect(statusTone('2')).toBe('bad')
    expect(statusTone('pending')).toBe('warn')
    expect(usedPct(100, 25)).toBe(75)
    expect(usedPct(0, 0)).toBe(0)
    expect(accountActionable({ name: 'root' })).toBe(false)
    expect(accountActionable({ name: 'jdoe', source: 'local' })).toBe(true)
  })
})
