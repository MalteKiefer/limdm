// Main flows of the dashboard areas: home, inbox with four eyes decisions
// (reject needs a reason, approve shows the new credentials once),
// activity with filters and the chain verification, reports with the
// compliance history and an export, and the global search.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, request, test, type APIRequestContext } from '@playwright/test'
import { baseURL } from '../playwright.config'
import { statePath } from './global-setup'
import { totp } from './totp'

test.use({ storageState: statePath })
test.describe.configure({ mode: 'serial' })

async function csrfOf(ctx: APIRequestContext) {
  return ((await (await ctx.get('/api/v1/me')).json()) as { csrf_token: string }).csrf_token
}

/**
 * Signs in a third admin of its own (the TOTP codes of the two from the
 * global setup are used by other specs; a code works only once).
 */
async function second(): Promise<APIRequestContext> {
  const bin = join(import.meta.dirname, '..', 'test-results', 'e2e', 'limdm-server')
  const env = { ...process.env, LIMDM_DATABASE_URL: process.env.LIMDM_E2E_DATABASE_URL }
  let out: string
  try {
    out = execFileSync(bin, ['local-admin', 'reset', 'e2edash'], { env, encoding: 'utf8' })
  } catch {
    out = execFileSync(bin, ['local-admin', 'add', 'e2edash'], { env, encoding: 'utf8' })
  }
  const get = (k: string) => new RegExp(`^${k}:\\s+(\\S+)`, 'm').exec(out)?.[1] ?? ''
  const ctx = await request.newContext({ baseURL, ignoreHTTPSErrors: true })
  const csrf = /name="csrf" value="([^"]+)"/.exec(await (await ctx.get('/login')).text())?.[1] ?? ''
  const res = await ctx.post('/login/local', { form: { csrf, username: 'e2edash', password: get('password'), totp: totp(get('secret')) }, headers: { Origin: baseURL }, maxRedirects: 0 })
  expect(res.status()).toBe(303)
  return ctx
}

async function fourEyes(ctx: APIRequestContext, on: boolean) {
  const res = await ctx.post('/settings', {
    form: { csrf: await csrfOf(ctx), section: 'security', min_length: '12', four_eyes: on ? 'on' : '' },
    headers: { Origin: baseURL },
    maxRedirects: 0,
  })
  expect(res.status()).toBeLessThan(400)
}

async function requestToken(ctx: APIRequestContext, name: string) {
  const res = await ctx.post('/api/v1/tokens', { data: { name, role: 'admin', days: 1 }, headers: { 'X-CSRF-Token': await csrfOf(ctx), Origin: baseURL } })
  expect(res.status()).toBe(202)
  return ((await res.json()) as { approval_id: number }).approval_id
}

test('home shows the situation and links into the lists', async ({ page }) => {
  await page.goto('/app/')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expect(page.getByText(/Compliance bei|Compliance at/).first()).toBeVisible()
})

test('inbox: reject needs a reason, approve shows the credentials once', async ({ page }) => {
  const me = await request.newContext({ baseURL, ignoreHTTPSErrors: true, storageState: statePath })
  const other = await second()
  await fourEyes(me, true)
  try {
    const rejectID = await requestToken(other, 'e2e-reject')
    const approveID = await requestToken(other, 'e2e-approve')

    await page.goto(`/app/inbox?item=a${rejectID}`)
    const sheet = page.getByRole('complementary')
    await expect(sheet.getByText('Admin API Token').first()).toBeVisible()
    await sheet.getByRole('button', { name: 'Ablehnen' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('button', { name: 'Ablehnen' }).click()
    await expect(dialog.getByText('Sag, warum du ablehnst.')).toBeVisible()
    await dialog.getByLabel(/Begründung der Entscheidung/).fill('not needed for the test')
    await dialog.getByRole('button', { name: 'Ablehnen' }).click()
    await expect(page.getByText('Abgelehnt').first()).toBeVisible()
    const rejected = await (await me.get(`/api/v1/approvals/${rejectID}`)).json()
    expect(rejected).toMatchObject({ status: 'rejected', decision_reason: 'not needed for the test' })

    // the selection moved on to another request
    await expect(page).not.toHaveURL(new RegExp(`item=a${rejectID}(&|$)`))
    await page.goto(`/app/inbox?item=a${approveID}`)
    await page.getByRole('complementary').getByRole('button', { name: 'Freigeben' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Freigeben' }).click()
    await expect(page.getByRole('dialog', { name: 'Zugangsdaten erstellt' })).toBeVisible()
    await page.keyboard.press('Escape')
    expect(((await (await me.get(`/api/v1/approvals/${approveID}`)).json()) as { status: string }).status).toBe('approved')
  } finally {
    await fourEyes(me, false)
    await other.dispose()
    await me.dispose()
  }
})

test('activity: timeline, filter, verify the chain', async ({ page }) => {
  await page.goto('/app/activity')
  await expect(page.getByRole('feed')).toBeVisible()
  await page.getByRole('group', { name: 'Art' }).getByRole('button', { name: 'Freigaben' }).click()
  await expect(page).toHaveURL(/cat=approvals/)
  await expect(page.getByRole('feed').getByText('approval.reject').first()).toBeVisible()
  // the result is either state: the CLI's local-admin entries of the global setup are not keyed
  await page.getByRole('button', { name: 'Ganze Kette prüfen' }).click()
  await expect(page.getByText(/Hash Kette vollständig geprüft|Die Hash Kette bricht bei Eintrag \d+\.$/).first()).toBeVisible()
  await expect(page.getByText(/Letzte vollständige Prüfung|Integritätsfehler/).first()).toBeVisible()
  const csv = await page.request.get('/api/v1/exports/audit.csv?action=approval')
  expect(csv.status()).toBe(200)
  expect(await csv.text()).toContain('approval.reject')
})

test('reports: compliance history and presets', async ({ page }) => {
  await page.goto('/app/reports')
  await expect(page.getByRole('heading', { name: 'Compliance zum Stichtag' })).toBeVisible()
  await expect(page.getByRole('link', { name: /Herunterladen: Inventar/ })).toHaveAttribute('href', '/api/v1/exports/inventory.csv')
  await page.getByLabel('Bericht', { exact: true }).selectOption('audit.jsonl')
  await page.getByLabel('Letzte Tage').fill('7')
  await expect(page.getByRole('link', { name: 'Bericht erzeugen' })).toHaveAttribute('href', /audit\.jsonl\?from=/)
})

test('reports: schedule a saved report and run it now', async ({ page }) => {
  const me = await request.newContext({ baseURL, ignoreHTTPSErrors: true, storageState: statePath })
  const csrf = await csrfOf(me)
  // a webhook channel to a private address: the server refuses to deliver there, no traffic leaves
  await me.post('/settings/notifications', { form: { csrf, name: `e2e-reports-${Date.now()}`, kind: 'webhook', url: 'https://127.0.0.1:9/hook' }, headers: { Origin: baseURL }, maxRedirects: 0 })
  const view = await me.post('/api/v1/views', { data: { list: 'reports', name: `Inventar e2e ${Date.now()}`, query: 'kind=inventory.csv' }, headers: { 'X-CSRF-Token': csrf, Origin: baseURL } })
  expect(view.status()).toBe(201)
  const { name } = (await view.json()) as { name: string }
  await me.dispose()

  await page.goto('/app/reports')
  const card = page.getByRole('region', { name: 'Zeitpläne' })
  await card.getByLabel(/Gespeicherter Bericht/).selectOption({ label: name })
  await card.getByLabel('Rhythmus').selectOption('monthly')
  await card.getByRole('checkbox').first().check()
  await card.getByRole('button', { name: 'Zeitplan speichern' }).click()
  await expect(page.getByText('Zeitplan gespeichert')).toBeVisible()
  const row = card.getByRole('listitem').filter({ hasText: name })
  await expect(row.getByText('monatlich')).toBeVisible()
  await row.getByRole('button', { name: 'Jetzt ausführen' }).click()
  await expect(page.getByText(/Bericht erzeugt und gesendet/)).toBeVisible()
  await row.getByText('Letzte Läufe').click()
  await expect(row.getByRole('link', { name: 'Herunterladen' }).first()).toHaveAttribute('href', /\/api\/v1\/report-runs\/\d+/)
})

test('home KPIs for security updates and current agents come from the API', async ({ page }) => {
  // the e2e database has no devices, so the tiles stay hidden behind the empty state
  const res = await page.request.get('/api/v1/stats/updates')
  expect(res.status()).toBe(200)
  expect(await res.json()).toMatchObject({ security_devices: 0, agent_total: 0, history: expect.any(Array) })
  expect((await page.request.get('/api/v1/stats/annotations?days=7')).status()).toBe(200)
})

test('global search finds the audit log', async ({ page }) => {
  await page.goto('/app/')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await page.keyboard.press('Control+k')
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.keyboard.type('e2e-approve')
  await expect(page.getByRole('dialog').getByText('Audit Log')).toBeVisible()
})
