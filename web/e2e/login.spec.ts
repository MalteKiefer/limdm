// Smoke test of the way in: the app sends signed out users to the login
// page; after a local sign in the app loads the user, the home page and its
// aggregates through the session API.
import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { credsPath, type Creds } from './global-setup'
import { totp } from './totp'

test('sign in and open the console app', async ({ page }) => {
  const { second } = JSON.parse(readFileSync(credsPath, 'utf8')) as { second: Creds }
  await page.goto('/app/devices')
  await expect(page).toHaveURL(/\/login\?next=%2Fapp%2Fdevices$/)
  await page.locator('input[name=username]').fill(second.user)
  await page.locator('input[name=password]').fill(second.password)
  await page.locator('input[name=totp]').fill(totp(second.secret))
  await page.locator('form[action="/login/local"] button').click()
  await page.waitForURL((u) => u.pathname === '/app/devices')

  const me = page.waitForResponse((r) => r.url().endsWith('/api/v1/me'))
  await page.goto('/app/')
  expect((await me).status()).toBe(200)
  await expect(page.getByRole('heading', { level: 1 })).toContainText(/e2esmoke/)
  await expect(page.getByRole('link', { name: /Geräte|Devices/ }).first()).toBeVisible()

  // a state change without the CSRF header is refused, with it the API accepts it
  const csrf = await page.evaluate(async () => (await (await fetch('/api/v1/me')).json()).csrf_token as string)
  const name = `Smoke ${Date.now()}`
  const body = { list: 'devices', name, query: 'status:stale' }
  const refused = await page.evaluate(async (b) => (await fetch('/api/v1/views', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })).status, body)
  expect(refused).toBe(403)
  const created = await page.evaluate(async ([b, token]) => {
    const r = await fetch('/api/v1/views', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: JSON.stringify(b) })
    return { status: r.status, id: ((await r.json()) as { id: number }).id }
  }, [body, csrf] as const)
  expect(created.status).toBe(201)
  await page.reload()
  await expect(page.getByRole('link', { name })).toBeVisible()
  const deleted = await page.evaluate(async ([id, token]) => (await fetch(`/api/v1/views/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': token } })).status, [created.id, csrf] as const)
  expect(deleted).toBe(204)
})
