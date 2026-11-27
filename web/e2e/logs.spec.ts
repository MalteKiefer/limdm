// Main flows of the Logs area against the real server: search across
// devices, filters, the detail sheet with context, export, the device tab,
// alert rules and the settings section.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath, locale: 'de-DE' })

test.beforeAll(() => {
  const repo = join(import.meta.dirname, '..', '..')
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'logs.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
})

test('search, filter, detail and export', async ({ page }) => {
  await page.goto('/app/logs')
  await expect(page.getByRole('heading', { name: 'Logs', level: 1, exact: true })).toBeVisible()
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Logs', exact: true })).toBeVisible()
  const grid = page.getByRole('table', { name: 'Logzeilen' })
  await expect(grid.getByText('WARNING slow consumer queue')).toBeVisible()
  await expect(grid.getByText(/Connection refused$/)).toBeVisible()
  await expect(page.getByRole('group', { name: /Histogramm mit/ })).toBeVisible()

  // query language
  await page.getByLabel('Abfrage').fill('"connection refused" prio<=err')
  await page.getByLabel('Abfrage').press('Enter')
  await expect(page).toHaveURL(/q=/)
  await expect(grid.getByText(/Connection refused$/)).toBeVisible()
  await expect(grid.getByText('status=deferred', { exact: false })).toHaveCount(0)
  await expect(grid.getByText('WARNING slow consumer queue')).toHaveCount(0)

  // detail sheet with fields and context
  await grid.getByText(/Connection refused$/).click()
  await expect(page).toHaveURL(/sel=/)
  const sheet = page.getByRole('complementary')
  await expect(sheet.getByText('postfix/smtp')).toBeVisible()
  await expect(sheet.getByRole('link', { name: 'e2e-mail' })).toBeVisible()
  await expect(sheet.getByText('Accepted publickey', { exact: false })).toBeVisible() // a context line after it

  // filters: source and device
  await page.getByRole('button', { name: 'Filter zurücksetzen' }).last().click()
  await page.getByLabel('Quelle').selectOption('container')
  await expect(page).toHaveURL(/source=container/)
  await expect(grid.getByText('WARNING slow consumer queue')).toBeVisible()
  await expect(grid.getByText(/Connection refused$/)).toHaveCount(0)

  // export, audited on the server
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Exportieren' }).click()
  await page.getByRole('menuitem', { name: /Als CSV/ }).click()
  expect((await download).suggestedFilename()).toBe('limdm-logs.csv')

  // live tail toggles
  await page.getByRole('button', { name: 'Live verfolgen' }).click()
  await expect(page).toHaveURL(/live=on/)
  await expect(page.getByRole('button', { name: 'Pausieren' })).toHaveAttribute('aria-pressed', 'true')
})

test('device tab shows only that device', async ({ page }) => {
  await page.goto('/app/devices/e2e-lg2?tab=logs')
  const grid = page.getByRole('table', { name: 'Logzeilen' })
  await expect(grid.getByText('GET /api/documents/ 200')).toBeVisible()
  await expect(grid.getByText(/Connection refused$/)).toHaveCount(0)
})

test('alert rules: create, test, delete', async ({ page }) => {
  await page.goto('/app/logs?tab=alerts')
  await page.getByRole('button', { name: 'Neue Alarmregel' }).click()
  const dialog = page.getByRole('dialog', { name: 'Neue Alarmregel' })
  await dialog.getByLabel('Name').fill('e2e mx down')
  await dialog.getByLabel('Abfrage').fill('"connection refused"')
  await dialog.getByLabel('Schwelle (Zeilen)').fill('1')
  await dialog.getByLabel('Zeitfenster (Minuten)').fill('60')
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Alarmregel gespeichert')).toBeVisible()
  await expect(page.getByText('e2e mx down')).toBeVisible()
  await page.getByRole('button', { name: 'Testen' }).click()
  await expect(page.getByText(/Schwelle erreicht/)).toBeVisible()
  await page.getByRole('button', { name: 'Alarmregel e2e mx down löschen' }).click()
  await page.getByRole('dialog', { name: 'Alarmregel e2e mx down löschen?' }).getByRole('button', { name: 'Löschen' }).click()
  await expect(page.getByText('Alarmregel gelöscht')).toBeVisible()
})

test('settings section', async ({ page }) => {
  await page.goto('/app/settings?s=logs')
  await expect(page.getByRole('heading', { name: 'Logs', level: 2, exact: true })).toBeVisible()
  const days = page.getByLabel('Tage auf dem Server')
  const want = (await days.inputValue()) === '14' ? '15' : '14'
  await days.fill(want)
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Gespeichert', { exact: false }).first()).toBeVisible()
  await page.reload()
  await expect(page.getByLabel('Tage auf dem Server')).toHaveValue(want)
  await expect(page.getByText('Zustand des Logspeichers')).toBeVisible()
  await expect(page.getByText('Archivschlüssel', { exact: true })).toBeVisible()
})

test('library item form: custom log directories with the root warning', async ({ page }) => {
  await page.goto('/app/config/library/new?type=com.limdm.logging')
  await expect(page.getByText('Eigene Logverzeichnisse').first()).toBeVisible()
  await expect(page.getByText(/liest Dateien unter diesen Verzeichnissen als root/).first()).toBeVisible()
})
