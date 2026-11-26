import { describe, expect, it } from 'vitest'
import { enrollConf, installCommand } from './enrolltext'
import { accountActionable, badParamLine, filterByName, formatUsers, mayCommand, parseTags, parseUsers, pkgValue, statusTone, usedPct } from './logic'

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

  it('parses desktop users like the console', () => {
    const r = parseUsers('jdoe Jane@Example.com admin\n\n  max max@example.com ')
    expect(r.error).toBeUndefined()
    expect(r.users).toEqual([
      { username: 'jdoe', email: 'jane@example.com', admin: true },
      { username: 'max', email: 'max@example.com', admin: false },
    ])
    expect(formatUsers(r.users)).toBe('jdoe jane@example.com admin\nmax max@example.com')
    expect(parseUsers('root r@x.de').error).toBe('root r@x.de')
    expect(parseUsers('a a@x.de\na b@x.de').error).toBe('a b@x.de')
    expect(parseUsers('a a@x.de sudo').error).toBeDefined()
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
