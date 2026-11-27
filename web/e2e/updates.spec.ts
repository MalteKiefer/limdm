// Main flows of the updates area against the real server: create a ring,
// start a wave, pause it; open CVEs with the devices they affect; package
// versions; the updates tab of a device with its rollback dialog.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath, locale: 'de-DE' })

test.beforeAll(() => {
  const repo = join(import.meta.dirname, '..', '..')
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'updates.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
})

test('rings: create, start a wave, pause and resume', async ({ page }) => {
  await page.goto('/app/updates')
  await expect(page.getByRole('heading', { name: 'Updates', level: 1 })).toBeVisible()
  await page.getByRole('button', { name: 'Ring anlegen' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Ring anlegen' })
  await dialog.getByLabel('Name').fill('e2e-pilot')
  await dialog.getByLabel('Tags').fill('e2epilot')
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Ring gespeichert')).toBeVisible()
  const rings = page.getByRole('table', { name: 'Updateringe' })
  const row = rings.getByRole('row', { name: /e2e-pilot/ })
  await expect(row).toBeVisible()
  await expect(row.getByText('#e2epilot')).toBeVisible()

  await page.getByRole('button', { name: 'Neue Welle starten' }).click()
  await expect(page.getByText(/Welle \d+ gestartet/)).toBeVisible()
  await expect(row.getByText(/Welle \d+/)).toBeVisible()

  await row.getByRole('button', { name: 'Anhalten' }).click()
  await expect(row.getByText('angehalten')).toBeVisible()
  await row.getByRole('button', { name: 'Fortsetzen' }).click()
  await expect(row.getByText('aktiv')).toBeVisible()
})

test('security: open CVEs lead to the affected devices', async ({ page }) => {
  await page.goto('/app/updates?tab=security')
  const cves = page.getByRole('table', { name: 'Offene CVEs' })
  await cves.getByRole('button', { name: 'CVE-2024-5535' }).click()
  await expect(page).toHaveURL(/cve=CVE-2024-5535/)
  await page.getByRole('table', { name: 'Geräte mit CVE-2024-5535' }).getByRole('link', { name: 'e2e-up1' }).click()
  await expect(page).toHaveURL(/devices\/e2e-up1.*tab=updates/)
  const pending = page.getByRole('table', { name: 'Ausstehende Updates' })
  await expect(pending.getByText('1:3.2.2-9.fc41')).toBeVisible()
  await expect(pending.getByText('Sicherheit · Important')).toBeVisible()
  await expect(page.getByRole('table', { name: 'Letzte Läufe' }).getByText('keine Updates')).toBeVisible()

  // rollback: the downgrade dialog explains its limits; cancel it
  await page.getByLabel('Paket', { exact: true }).fill('openssl')
  await page.getByRole('button', { name: 'Zurückstufen' }).click()
  const confirm = page.getByRole('dialog', { name: 'openssl zurückstufen?' })
  await expect(confirm.getByText(/Nur Debian, Ubuntu und dnf/)).toBeVisible()
  await confirm.getByRole('button', { name: 'Abbrechen' }).click()
})

test('versions: installed versions of a package', async ({ page }) => {
  await page.goto('/app/updates?tab=versions')
  await page.getByRole('textbox', { name: 'Paket' }).fill('openssl')
  await page.getByRole('button', { name: 'Anzeigen' }).click()
  await expect(page).toHaveURL(/pkg=openssl/)
  await expect(page.getByRole('table', { name: 'Installierte Versionen' }).getByText('1:3.2.2-1.fc41')).toBeVisible()
})

test('cve data: settings form, feed state and CVEs matched for Ubuntu', async ({ page }) => {
  // the form only, never switched on here: that would download from the internet
  await page.goto('/app/settings?s=cve')
  await expect(page.getByRole('heading', { name: 'CVE Daten' })).toBeVisible()
  await page.getByLabel('Adresse Debian Security Tracker (JSON)').fill('http://mirror.example/json')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Nur https Adressen.')).toBeVisible()

  await page.goto('/app/updates?tab=security')
  const feeds = page.getByRole('table', { name: 'CVE Daten für Debian und Ubuntu' })
  await expect(feeds.getByRole('row', { name: /Ubuntu \(OSV\)/ }).getByText('42')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Jetzt aktualisieren' })).toBeDisabled()
  await page.getByRole('table', { name: 'Offene CVEs' }).getByRole('button', { name: 'CVE-2024-6387' }).click()
  await page.getByRole('table', { name: 'Geräte mit CVE-2024-6387' }).getByRole('link', { name: 'e2e-up2' }).click()
  await expect(page.getByRole('table', { name: 'Bekannte Schwachstellen' }).getByText('1:9.6p1-3ubuntu13.3')).toBeVisible()
  await expect(page.getByRole('table', { name: 'Ausstehende Updates' }).getByText('CVE-2024-6387')).toBeVisible()
})
