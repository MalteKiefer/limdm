// Main flows of the compliance area against the real server: overview,
// risk exception create and revoke (with the four eyes rule checked in the
// form), history, policies, and the evidence export whose SHA-256 matches
// its export.done audit entry.
import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath })

test('overview and the compliance sections', async ({ page }) => {
  await page.goto('/app/compliance')
  await expect(page.getByRole('heading', { level: 1, name: 'Compliance' })).toBeVisible()
  const sections = page.getByRole('navigation', { name: 'Bereiche der Compliance' })
  await expect(page.getByText('Gesamtscore').or(page.getByText('Noch keine Prüfergebnisse'))).toBeVisible()

  await sections.getByRole('link', { name: 'Richtlinien' }).click()
  await expect(page).toHaveURL(/\/app\/compliance\/policies$/)
  await expect(page.getByRole('heading', { name: 'CIS Level 1 baseline' })).toBeVisible()
  await expect(page.getByText('Karenzzeit und automatische Sperre')).toBeVisible()

  await sections.getByRole('link', { name: 'Verlauf' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Compliance Verlauf' })).toBeVisible()
  await page.getByLabel('Stichtag').fill('2026-01-15')
  await expect(page).toHaveURL(/at=2026-01-15/)
  await expect(page.getByText('Geräte am')).toBeVisible()
})

test('add and revoke a risk exception', async ({ page }) => {
  const check = `e2e.check${Date.now() % 100000}`
  await page.goto('/app/compliance/exceptions')
  await page.getByRole('button', { name: 'Ausnahme anlegen' }).click()
  const dialog = page.getByRole('dialog', { name: 'Risikoausnahme anlegen' })
  await dialog.getByRole('button', { name: 'Ausnahme anlegen' }).click()
  await expect(dialog.getByLabel(/Begründung/)).toHaveAttribute('aria-invalid', 'true')

  await dialog.getByLabel(/Prüfungs ID/).fill(check)
  await dialog.getByLabel(/Geräte Tag/).fill('lab')
  await dialog.getByLabel(/Begründung/).fill('Laborgeräte routen absichtlich')
  await dialog.getByLabel(/Risikoverantwortlich/).fill('CTO')
  await dialog.getByLabel(/Freigegeben von/).fill('ciso@firma.de')
  const next = new Date(Date.now() + 30 * 86400_000)
  await dialog.getByLabel(/Gültig bis/).fill(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}-${String(next.getDate()).padStart(2, '0')}`)
  await dialog.getByRole('button', { name: 'Ausnahme anlegen' }).click()
  await expect(dialog).toBeHidden()
  const row = page.getByRole('row', { name: new RegExp(check.replace('.', '\\.')) })
  await expect(row).toContainText('aktiv')

  await row.getByRole('button', { name: 'Widerrufen' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Widerrufen' }).click()
  await expect(row).toBeHidden()
  await page.getByRole('tab', { name: /widerrufen/ }).click()
  await expect(page.getByRole('row', { name: new RegExp(check.replace('.', '\\.')) })).toContainText('widerrufen')
})

test('evidence export matches its audit entry', async ({ page }) => {
  await page.goto('/app/compliance?export=1')
  const dialog = page.getByRole('dialog', { name: 'Nachweis exportieren' })
  let prev = ''
  for (const kind of ['evidence.pdf', 'evidence.json', 'compliance.csv']) {
    await dialog.getByRole('radio', { name: new RegExp(kind.replace('.', '\\.')) }).check()
    const download = page.waitForEvent('download')
    await dialog.getByRole('button', { name: 'Herunterladen' }).click()
    const file = await download
    expect(file.suggestedFilename()).toMatch(new RegExp(`${kind.replace('.', '\\.')}$`))
    const sha = dialog.locator('code')
    await expect(sha).not.toHaveText(prev)
    prev = (await sha.textContent()) ?? ''
    await expect(dialog.getByText(/stimmt mit Audit Eintrag #\d+ überein/)).toBeVisible()
    if (kind === 'evidence.json') {
      const body = JSON.parse(readFileSync(await file.path(), 'utf8')) as { payload: { format: string }; signature: { alg: string } }
      expect(body.payload.format).toBe('limdm-evidence/1')
      expect(body.signature.alg).toBe('ed25519')
    }
  }
})

test('request a risk exception through the inbox', async ({ page }) => {
  // four eyes on for this page only: the form becomes a request
  await page.route('**/api/v1/me', async (route) => {
    const res = await route.fetch()
    await route.fulfill({ response: res, json: { ...(await res.json()), four_eyes: true } })
  })
  const check = `e2e.req${Date.now() % 100000}`
  await page.goto(`/app/compliance/exceptions?new=${check}`)
  const dialog = page.getByRole('dialog', { name: 'Risikoausnahme beantragen' })
  await expect(dialog.getByLabel(/Freigegeben von/)).toHaveCount(0)
  await dialog.getByLabel(/Begründung/).fill('Altgerät bis zur Ablösung')
  await dialog.getByLabel(/Risikoverantwortlich/).fill('CTO')
  const next = new Date(Date.now() + 14 * 86400_000)
  await dialog.getByLabel(/Gültig bis/).fill(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}-${String(next.getDate()).padStart(2, '0')}`)
  const posted = page.waitForResponse((r) => r.url().endsWith('/api/v1/exception-requests'))
  await dialog.getByRole('button', { name: 'Antrag stellen' }).click()
  expect((await posted).status()).toBe(202)
  await expect(dialog).toBeHidden()
  const pending = await page.evaluate(async () => (await (await fetch('/api/v1/approvals?status=pending')).json()) as { items: { id: number; action: string; target: string }[] })
  const req = pending.items.find((a) => a.action === 'exception.add' && a.target === check)
  expect(req).toBeTruthy()
  // the requester cannot approve their own request
  const csrf = await page.evaluate(async () => (await (await fetch('/api/v1/me')).json()).csrf_token as string)
  const own = await page.evaluate(async ([id, token]) => (await fetch(`/api/v1/approvals/${id}/approve`, { method: 'POST', headers: { 'X-CSRF-Token': token } })).status, [req!.id, csrf] as const)
  expect(own).toBe(409)
})
