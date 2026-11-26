// Signs in a local admin of its own for a spec: a TOTP code works only
// once, and every session has its own API rate limit, so a spec that
// loads many pages does not starve the next one.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, request, type APIRequestContext } from '@playwright/test'
import { baseURL } from '../playwright.config'
import { totp } from './totp'

export async function signIn(name: string): Promise<APIRequestContext> {
  const dir = join(import.meta.dirname, '..', 'test-results', 'e2e')
  const env = { ...process.env, LIMDM_DATABASE_URL: process.env.LIMDM_E2E_DATABASE_URL, LIMDM_CA_DIR: join(dir, 'ca') }
  let out: string
  try {
    out = execFileSync(join(dir, 'limdm-server'), ['local-admin', 'reset', name], { env, encoding: 'utf8' })
  } catch {
    out = execFileSync(join(dir, 'limdm-server'), ['local-admin', 'add', name], { env, encoding: 'utf8' })
  }
  const get = (k: string) => new RegExp(`^${k}:\\s+(\\S+)`, 'm').exec(out)?.[1] ?? ''
  const ctx = await request.newContext({ baseURL, ignoreHTTPSErrors: true })
  const csrf = /name="csrf" value="([^"]+)"/.exec(await (await ctx.get('/login')).text())?.[1] ?? ''
  const res = await ctx.post('/login/local', { form: { csrf, username: name, password: get('password'), totp: totp(get('secret')) }, headers: { Origin: baseURL }, maxRedirects: 0 })
  expect(res.status()).toBe(303)
  return ctx
}
