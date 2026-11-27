// Every console language on the main pages: the page is in that language,
// no message key shows raw, no CSP violation, nothing wider than a 390 px
// phone; server written texts (agent events, check titles) follow the language.
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { signIn } from './signin'

const repo = join(import.meta.dirname, '..', '..')
const src = join(import.meta.dirname, '..', 'src')

// the German keys of every catalog (the source of all languages)
const keys = [join(src, 'i18n', 'core.ts'), ...readdirSync(join(src, 'areas')).map((a) => join(src, 'areas', a, 'messages.ts'))].flatMap((f) => {
  const s = readFileSync(f, 'utf8')
  return [...s.slice(0, s.indexOf('export const en')).matchAll(/^\s*'([a-z][\w.-]*\.[\w.-]+)':/gm)].map((m) => m[1])
})

const pages = ['/app/', '/app/inbox', '/app/devices', '/app/devices/e2e-i18n', '/app/devices/e2e-i18n?tab=activity', '/app/compliance', '/app/config', '/app/updates', '/app/vulnerabilities', '/app/logs', '/app/activity', '/app/reports', '/app/settings', '/app/settings?s=notifications', '/app/profile', '/app/help']

// what each language shows for the seeded agent event and check (internal/server/i18n_*.go)
const expected = {
  de: { nav: 'Navigation öffnen', event: 'Deklarationen aktualisiert (Token 42)' },
  en: { nav: 'Open navigation', event: 'declarations updated (token 42)' },
  fr: { nav: 'Ouvrir la navigation', event: 'déclarations mises à jour (jeton 42)' },
  es: { nav: 'Abrir navegación', event: 'declaraciones actualizadas (token 42)' },
  it: { nav: 'Apri navigazione', event: 'dichiarazioni aggiornate (token 42)' },
  ru: { nav: 'Открыть навигацию', event: 'декларации обновлены (токен 42)' },
}

test.beforeAll(() => {
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'i18n.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
})

// Two languages share one admin: sign ins count against the login limit of
// the source address (10 in 5 minutes) that login.spec.ts still needs, and
// each session keeps its own API rate limit.
const sessions = new Map<number, ReturnType<typeof signIn>>()
const session = (i: number) => {
  const n = Math.floor(i / 2)
  if (!sessions.has(n)) sessions.set(n, signIn(`e2ei18n${n}`))
  return sessions.get(n)!
}
test.afterAll(async () => {
  for (const s of sessions.values()) await (await s).dispose()
})

for (const [i, [locale, want]] of Object.entries(expected).entries()) {
  test(`console in ${locale}: no raw keys, no CSP errors, fits 390 px`, async ({ browser }) => {
    test.setTimeout(pages.length * 8_000)
    const api = await session(i)
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 390, height: 844 }, storageState: await api.storageState() })
    const page = await ctx.newPage()
    const problems: string[] = []
    page.on('console', (m) => {
      if (/Content Security Policy|Content-Security-Policy/i.test(m.text())) problems.push(m.text())
    })
    page.on('pageerror', (e) => problems.push(`page error: ${e.message}`))
    // the choice of the profile: stored in the browser and sent to the server
    await page.goto('/app/profile')
    await page.evaluate((l) => localStorage.setItem('limdm.prefs', JSON.stringify({ locale: l })), locale)
    await page.request.get(`/lang/${locale}`, { maxRedirects: 0 })
    for (const p of pages) {
      await page.goto(p)
      await expect(page.locator('html')).toHaveAttribute('lang', locale)
      await expect(page.getByRole('button', { name: want.nav })).toBeVisible() // the phone menu button, in the language
      await page.waitForLoadState('networkidle')
      // visible text without code: action codes, check IDs and paths in mono type are data
      const text = await page.evaluate(() => {
        const b = document.body.cloneNode(true) as HTMLElement
        b.querySelectorAll('code, pre, kbd, .font-mono').forEach((e) => e.remove())
        return b.textContent ?? ''
      })
      // a key as a whole word (check IDs such as updates.security_age are data, not keys)
      expect(keys.filter((k) => text.includes(k) && new RegExp(`(^|[^\\w.-])${k.replace(/\./g, '\\.')}($|[^\\w.-])`).test(text)), `raw keys on ${p}`).toEqual([])
      const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(wide, `horizontal overflow on ${p}`).toBeLessThanOrEqual(1)
      if (p.endsWith('tab=activity')) await expect(page.getByText(want.event)).toBeVisible()
    }
    expect(problems).toEqual([])
    await ctx.close()
  })
}
