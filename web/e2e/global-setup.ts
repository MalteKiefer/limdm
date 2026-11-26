// Builds and starts a LiMDM server for the end to end tests: TLS on
// localhost with a throw away certificate, local login, its own database
// (LIMDM_E2E_DATABASE_URL). Creates two local admins with fresh
// credentials and signs the first one in for the tests that need a session.
import { execFileSync, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { request } from '@playwright/test'
import { baseURL, port } from '../playwright.config'
import { totp } from './totp'

const dir = join(import.meta.dirname, '..', 'test-results', 'e2e')
export const statePath = join(dir, 'state.json')
export const credsPath = join(dir, 'creds.json')

async function waitFor(url: string, ms = 60_000) {
  const until = Date.now() + ms
  const ctx = await request.newContext({ ignoreHTTPSErrors: true })
  try {
    while (Date.now() < until) {
      try {
        if ((await ctx.get(url)).ok()) return
      } catch {
        // not up yet
      }
      await new Promise((r) => setTimeout(r, 300))
    }
    throw new Error(`server did not answer ${url}`)
  } finally {
    await ctx.dispose()
  }
}

export type Creds = { user: string; password: string; secret: string }

function localAdmin(bin: string, env: NodeJS.ProcessEnv, name: string): Creds {
  let out: string
  try {
    out = execFileSync(bin, ['local-admin', 'reset', name], { env, encoding: 'utf8' })
  } catch {
    out = execFileSync(bin, ['local-admin', 'add', name], { env, encoding: 'utf8' })
  }
  const get = (k: string) => new RegExp(`^${k}:\\s+(\\S+)`, 'm').exec(out)?.[1] ?? ''
  return { user: name, password: get('password'), secret: get('secret') }
}

export default async function globalSetup() {
  const db = process.env.LIMDM_E2E_DATABASE_URL
  if (!db) throw new Error('set LIMDM_E2E_DATABASE_URL to a disposable PostgreSQL database for the end to end tests')
  mkdirSync(join(dir, 'ca'), { recursive: true })
  const repo = join(import.meta.dirname, '..', '..')
  const bin = join(dir, 'limdm-server')
  execFileSync('go', ['build', '-o', bin, './cmd/limdm-server'], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
  const cert = join(dir, 'tls.crt')
  const key = join(dir, 'tls.key')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert], { stdio: 'ignore' })
  // the server seals secrets in the database with the session key: keep it across runs
  const keyFile = join(dir, 'session.key')
  if (!existsSync(keyFile)) writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 })
  const env = {
    ...process.env,
    LIMDM_DATABASE_URL: db,
    LIMDM_PUBLIC_URL: baseURL,
    LIMDM_LISTEN: `localhost:${port}`,
    LIMDM_TLS_CERT: cert,
    LIMDM_TLS_KEY: key,
    LIMDM_AGENT_URL: `https://127.0.0.1:${port + 1}`,
    LIMDM_AGENT_LISTEN: `127.0.0.1:${port + 1}`,
    LIMDM_CA_DIR: join(dir, 'ca'),
    LIMDM_LOCAL_LOGIN: 'true',
    LIMDM_SESSION_KEY: readFileSync(keyFile, 'utf8'),
  }
  const server = spawn(bin, ['serve'], { env, stdio: ['ignore', 'ignore', 'inherit'] })
  await waitFor(`${baseURL}/healthz`)

  const creds = { first: localAdmin(bin, env, 'e2e'), second: localAdmin(bin, env, 'e2esmoke') }
  writeFileSync(credsPath, JSON.stringify(creds))

  // sign in the first account once; tests reuse the session cookie
  const ctx = await request.newContext({ baseURL, ignoreHTTPSErrors: true })
  const page = await ctx.get('/login')
  const csrf = /name="csrf" value="([^"]+)"/.exec(await page.text())?.[1] ?? ''
  const res = await ctx.post('/login/local', {
    form: { csrf, username: creds.first.user, password: creds.first.password, totp: totp(creds.first.secret) },
    headers: { Origin: baseURL },
    maxRedirects: 0,
  })
  if (res.status() !== 303) throw new Error(`sign in failed: ${res.status()}`)
  await ctx.storageState({ path: statePath })
  await ctx.dispose()

  return async () => {
    server.kill('SIGTERM')
  }
}
