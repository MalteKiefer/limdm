// A software request shows in the bell and the inbox while the console is
// open; host name confirmations show the name to type as code; the device
// message has a multi line field with a counter.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath, locale: 'de-DE' })

const repo = join(import.meta.dirname, '..', '..')
const seed = (file: string) => execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, file)], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })

test.beforeAll(() => seed('instant.seed.sql'))

const openCount = async (label: string | null) => Number(/(\d+) offen/.exec(label ?? '')?.[1] ?? 0)

test('a new software request appears in the bell and the inbox', async ({ page }) => {
  await page.goto('/app/devices')
  const bell = page.getByRole('link', { name: /^Eingang, \d+ offen$/ })
  await expect(bell).toBeVisible()
  const before = await openCount(await bell.getAttribute('aria-label'))
  seed('instant-request.seed.sql')
  // the event stream asks every three seconds
  await expect(page.getByRole('link', { name: `Eingang, ${before + 1} offen` })).toBeVisible({ timeout: 15_000 })
  await page.getByRole('link', { name: `Eingang, ${before + 1} offen` }).click()
  await page.getByRole('tab', { name: /Softwareanfragen/ }).click()
  await page.getByRole('link', { name: /E2E Instant angefragt auf e2e-inst1/ }).click()
  await expect(page.getByText('for the bell test')).toBeVisible()
  await page.getByRole('link', { name: 'Anfrage entscheiden' }).click()
  await expect(page).toHaveURL(/tab=software/)
  await expect(page.getByRole('listitem').filter({ hasText: 'E2E Instant' }).filter({ hasText: 'e2e-inst1' })).toBeVisible()
})

test('host name confirmation shows the name as code, message field is multi line', async ({ page }) => {
  await page.goto('/app/devices/e2e-inst1')
  await page.getByRole('button', { name: 'Aktionen für e2e-inst1' }).click()
  await page.getByRole('menuitem', { name: 'Verlustmodus', exact: true }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.locator('label code')).toHaveText('e2e-inst1')
  await expect(dlg.getByLabel(/Zur Bestätigung den Hostnamen e2e-inst1 eingeben/)).toBeVisible()
  await dlg.getByRole('button', { name: 'Abbrechen' }).click()

  await page.getByRole('button', { name: 'Aktionen für e2e-inst1' }).click()
  await page.getByRole('menuitem', { name: 'Nachricht senden' }).click()
  const msg = page.getByRole('dialog').getByRole('textbox', { name: /^Nachricht/ })
  await expect(msg).toHaveAttribute('rows', '6')
  // six lines, also in the compact density (its one line field height once won)
  await expect.poll(async () => msg.evaluate((el) => el.getBoundingClientRect().height + ' ' + getComputedStyle(el).height)).toMatch(/^\d{3}/)
  await msg.fill('Bitte heute neu starten')
  await expect(page.getByRole('dialog').getByText('23 / 1000')).toBeVisible()
})
