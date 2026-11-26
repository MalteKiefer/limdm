import { describe, expect, it } from 'vitest'
import { addToken, hasToken, removeToken, serialize, tokenize, trailing } from './query'

describe('query language', () => {
  it('tokenizes keys, quotes and free text', () => {
    expect(tokenize('web status:non-compliant os:"Ubuntu 24"')).toEqual([
      { key: null, value: 'web' },
      { key: 'status', value: 'non-compliant' },
      { key: 'os', value: 'Ubuntu 24' },
    ])
  })
  it('round trips', () => {
    const q = 'tag:prod os:"Debian 12" web'
    expect(serialize(tokenize(q))).toBe(q)
  })
  it('adds a token once and removes it', () => {
    let q = addToken('tag:prod', { key: 'status', value: 'stale' })
    expect(q).toBe('tag:prod status:stale')
    expect(addToken(q, { key: 'status', value: 'STALE' })).toBe(q)
    expect(hasToken(q, { key: 'tag', value: 'prod' })).toBe(true)
    q = removeToken(q, { key: 'tag', value: 'prod' })
    expect(q).toBe('status:stale')
  })
  it('finds the key being typed', () => {
    expect(trailing('tag:prod sta')).toEqual({ key: 'sta', value: '' })
    expect(trailing('status:non')).toEqual({ key: 'status', value: 'non' })
  })
})
