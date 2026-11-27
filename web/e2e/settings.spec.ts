// Main flows of the settings area against the real server: section forms
// with validation and saving, users with credentials shown once, API tokens,
// notification channels, a backup schedule preview, profile and help.
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath, locale: 'de-DE' })

const stamp = () => Date.now().toString(36)

test('a section form validates, saves and keeps the value', async ({ page }) => {
  const csp: string[] = []
  page.on('console', (m) => /Content Security Policy|unsafe-eval/i.test(m.text()) && csp.push(m.text()))
  await page.goto('/app/settings?s=general')
  const stale = page.getByLabel('Gerät gilt als veraltet nach (Stunden)')
  await expect(stale).toBeVisible()
  const before = await stale.inputValue()
  await stale.fill('0')
  await stale.blur()
  await expect(stale).toHaveAttribute('aria-invalid', 'true')
  await expect(page.getByText('1 bis 2160 Stunden').first()).toBeVisible()
  const next = before === '30' ? '31' : '30'
  await stale.fill(next)
  await expect(page.getByRole('region', { name: 'Ungespeicherte Änderungen' })).toBeVisible()
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Gespeichert und aktiv.').first()).toBeVisible()
  await page.reload()
  await expect(page.getByLabel('Gerät gilt als veraltet nach (Stunden)')).toHaveValue(next)
  await expect(page.getByRole('region', { name: 'Ungespeicherte Änderungen' })).toHaveCount(0)
  expect(csp).toEqual([])
})

// a 1x1 PNG
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

test('the logo preview is drawn from the picked file, within the CSP', async ({ page }) => {
  const csp: string[] = []
  page.on('console', (m) => /Content Security Policy/i.test(m.text()) && csp.push(m.text()))
  await page.goto('/app/settings?s=general')
  await page.getByLabel('PNG auswählen').setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer: png })
  const preview = page.getByRole('img', { name: 'Vorschau des Logos' })
  await expect(preview).toBeVisible()
  expect(await preview.evaluate((e) => e.tagName)).toBe('CANVAS')
  await expect.poll(() => preview.evaluate((e) => (e as HTMLCanvasElement).width)).toBe(1)
  expect(csp).toEqual([])
})

test('a network list rejects what is no address', async ({ page }) => {
  await page.goto('/app/settings?s=access')
  const allow = page.getByLabel('Erlaubte Netze', { exact: true })
  await allow.fill('10.0.0.0/8 nonsense')
  await allow.blur()
  await expect(page.getByText('„nonsense“ ist keine Adresse und kein CIDR Bereich.')).toBeVisible()
  await page.getByRole('button', { name: 'Verwerfen' }).click()
  await expect(allow).toHaveValue('')
})

test('add a local user, see the credentials once, scope it', async ({ page }) => {
  const name = `ops${stamp()}`
  await page.goto('/app/settings?s=users')
  await page.getByRole('button', { name: 'Benutzer hinzufügen' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Art').selectOption('local')
  await dialog.getByLabel('Lokaler Name').fill(name)
  await dialog.getByLabel('Rolle').selectOption('helpdesk')
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  const creds = page.getByRole('dialog', { name: 'Zugangsdaten erstellt' })
  await expect(creds).toBeVisible()
  await expect(creds.getByLabel('Geheimnis')).toContainText(`user:     ${name}`)
  await creds.getByRole('button', { name: 'Fertig' }).click()
  await page.getByRole('row', { name: new RegExp(name) }).click()
  const sheet = page.getByRole('complementary')
  await sheet.getByLabel('Bereich: Gerätetags').fill('berlin')
  await sheet.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByRole('row', { name: new RegExp(`${name}.*berlin`) })).toBeVisible()
  // the own account cannot be demoted here
  await page.getByRole('row', { name: /e2e Sie/ }).click()
  await expect(page.getByRole('complementary').getByLabel('Rolle')).toBeDisabled()
})

test('create an API token, shown once, then revoke it', async ({ page }) => {
  const name = `report-${stamp()}`
  await page.goto('/app/settings?s=tokens')
  await page.getByRole('button', { name: 'Token erstellen' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill(name)
  await dialog.getByLabel('Rolle').selectOption('auditor')
  await dialog.getByRole('checkbox', { name: 'Lesen' }).check()
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  const secret = page.getByRole('dialog', { name: 'Token erstellt' })
  await expect(secret.getByLabel('Geheimnis')).toContainText('lma_')
  await secret.getByRole('button', { name: 'Fertig' }).click()
  const row = page.getByRole('row', { name: new RegExp(name) })
  await row.getByRole('button', { name: `Widerrufen ${name}` }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Widerrufen' }).click()
  await expect(row.getByText('widerrufen')).toBeVisible()
})

test('add and delete a notification channel', async ({ page }) => {
  const name = `Hook ${stamp()}`
  await page.goto('/app/settings?s=notifications')
  await page.getByRole('button', { name: 'Kanal hinzufügen' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('radio', { name: /^Webhook/ }).check()
  await dialog.getByLabel('Name').fill(name)
  await dialog.getByLabel('Webhook URL').fill('http://insecure.example')
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  await expect(dialog.getByText('Eine https URL eingeben.')).toBeVisible()
  await dialog.getByLabel('Webhook URL').fill('https://hooks.example.com/limdm')
  await dialog.getByLabel(/Gerät registriert/).check()
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row).toContainText('Gerät registriert')
  await row.getByRole('button', { name: `Aktionen für ${name}` }).click()
  await page.getByRole('menuitem', { name: 'Löschen' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Löschen' }).click()
  await expect(row).toHaveCount(0)
})

test('a backup schedule shows its next runs before saving', async ({ page }) => {
  const dir = mkdtempSync(join(tmpdir(), 'limdm-e2e-backup-'))
  const target = `disk${stamp()}`
  await page.goto('/app/settings?s=backup')
  await page.getByRole('button', { name: 'Ziel hinzufügen' }).click()
  let dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill(target)
  await dialog.getByLabel('Verzeichnis').fill(dir)
  await dialog.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText(target, { exact: true })).toBeVisible()
  await page.getByRole('listitem').filter({ hasText: target }).getByRole('button', { name: 'Testen' }).click()
  await expect(page.getByText(/ok|written|geschrieben/i).first()).toBeVisible()
  await page.getByRole('button', { name: 'Plan hinzufügen' }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill('e2e_nightly')
  await expect(dialog.getByText('Nächste Läufe:')).toBeVisible()
  await expect(dialog.getByRole('region').or(dialog.locator('section[aria-live]')).getByRole('listitem')).toHaveCount(5)
  await dialog.getByLabel('Zeitplan').selectOption('cron')
  await dialog.getByLabel('Cron').fill('0 2 *')
  await expect(dialog.getByText('Erscheint, sobald der Plan vollständig ist.')).toBeVisible()
  await dialog.getByRole('button', { name: 'Schließen' }).click()
})

test('profile and help', async ({ page }) => {
  await page.goto('/app/profile')
  await expect(page.getByRole('heading', { level: 1, name: 'Profil' })).toBeVisible()
  await expect(page.getByLabel('Aktuelles Passwort').first()).toBeVisible()
  await page.getByRole('radio', { name: 'Kompakt' }).or(page.getByRole('button', { name: 'Kompakt' })).first().click()
  await expect(page.locator('html')).toHaveAttribute('data-density', 'compact')
  await page.getByRole('radio', { name: 'Komfortabel' }).or(page.getByRole('button', { name: 'Komfortabel' })).first().click()
  await page.goto('/app/help')
  await expect(page.getByRole('heading', { name: 'Glossar' })).toBeVisible()
  await page.getByPlaceholder('Begriffe filtern').fill('Blueprint')
  await expect(page.locator('dt').filter({ hasText: /Blueprint/ }).first()).toBeVisible()
})

test('a sign in started in the app returns there', async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, storageState: { cookies: [], origins: [] } })
  const page = await ctx.newPage()
  await page.goto('/app/settings?s=users')
  await expect(page).toHaveURL(/\/login\?next=%2Fapp%2Fsettings%3Fs%3Dusers$/)
  await expect(page.locator('input[name=next]')).toHaveValue('/app/settings?s=users')
  await page.goto('/login?next=https%3A%2F%2Fevil.example%2F')
  await expect(page.locator('input[name=next]')).toHaveValue('/app/')
  await ctx.close()
})

test('deep links by section name open the section', async ({ page }) => {
  await page.goto('/app/settings/branding')
  await expect(page).toHaveURL(/\/app\/settings\?s=general$/)
  await expect(page.getByRole('heading', { name: 'Branding', exact: true })).toBeVisible()
  await page.goto('/app/settings/sso')
  await expect(page).toHaveURL(/\/app\/settings\?s=signin$/)
})

test('the deep links of the first steps land on their screens', async ({ page }) => {
  await page.goto('/app/settings/enrollment')
  await expect(page).toHaveURL(/\/app\/devices\/enroll$/)
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await page.goto('/app/config?tab=blueprints')
  await expect(page.getByRole('tab', { name: 'Blueprints', selected: true })).toBeVisible()
  await page.goto('/')
  await expect(page).toHaveURL(/\/app\/$/)
  await page.goto('/library/1')
  await expect(page).toHaveURL(/\/app\/config\/library\/1$/)
})

test('enrollment limits bound the add device form; certificate domain saves', async ({ page }) => {
  await page.goto('/app/settings?s=enroll')
  const max = page.getByLabel('Höchste Zahl an Nutzungen')
  await max.fill('501')
  await max.blur()
  await expect(max).toHaveAttribute('aria-invalid', 'true')
  await max.fill('10')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Gespeichert und aktiv.').first()).toBeVisible()
  await page.goto('/app/devices/enroll')
  const uses = page.getByLabel('Nutzungen', { exact: true })
  await expect(uses).toHaveValue('1')
  await uses.fill('11')
  await expect(page.getByText('1 bis 10 (Einstellungen, Registrierung)')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Token erstellen' })).toBeDisabled()
  await page.goto('/app/settings?s=enroll')
  await page.getByLabel('Höchste Zahl an Nutzungen').fill('500')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Gespeichert und aktiv.').first()).toBeVisible()

  await page.goto('/app/settings?s=network')
  const domain = page.getByLabel('Domain', { exact: true })
  await domain.fill('Not a domain')
  await domain.blur()
  await expect(page.getByText('Eine DNS Domain in Kleinbuchstaben, z. B. devices.example.com')).toBeVisible()
  await domain.fill('devices.example.com')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Gespeichert und aktiv.').first()).toBeVisible()
  await page.reload()
  await expect(page.getByLabel('Domain', { exact: true })).toHaveValue('devices.example.com')
})
