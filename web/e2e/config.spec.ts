// Main flows of the configuration area against a real server: every
// declaration type as a form, a library item from the type picker to a
// rollback, a blueprint with a condition, the software catalog settings
// and remotes, and a package upload. LIMDM_E2E_SHOTS=<dir> also saves
// screenshots of the screens.
import { execFileSync } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test, type Page } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath })
test.describe.configure({ mode: 'serial' })

const stamp = Date.now().toString(36)
const shots = process.env.LIMDM_E2E_SHOTS

async function shoot(page: Page, name: string) {
  if (!shots) return
  mkdirSync(shots, { recursive: true })
  for (const [w, h] of [
    [1440, 900],
    [390, 844],
  ]) {
    await page.setViewportSize({ width: w, height: h })
    await page.waitForTimeout(250)
    await page.screenshot({ path: join(shots, `${name}-${w}.png`), fullPage: true })
  }
  await page.setViewportSize({ width: 1440, height: 900 })
}

test('every declaration type has a form without JSON', async ({ page }) => {
  test.setTimeout(180_000) // 35 page loads; CI runners are slower than 30 s allows
  await page.goto('/app/config?tab=library')
  const types = await page.evaluate(async () => ((await (await fetch('/api/v1/schemas?lang=de')).json()).items as { type: string }[]).map((x) => x.type))
  expect(types.length).toBe(35)
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  for (const type of types) {
    await page.goto(`/app/config/library/new?type=${type}`)
    await expect(page.getByRole('group', { name: 'Einstellungen des Elements' })).toBeVisible()
    // the form, not the JSON editor, and at least one labelled control from the schema
    await expect(page.getByRole('radio', { name: 'Formular' })).toHaveAttribute('aria-checked', 'true')
    await expect(page.locator('fieldset.card').first()).toBeVisible()
  }
  expect(errors).toEqual([])
})

test('host name item: warning and preview', async ({ page }) => {
  await page.goto('/app/config/library/new?type=com.limdm.hostname')
  await expect(page.getByRole('note').filter({ hasText: 'Ein neuer Hostname kann Dienste stören' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Vorschau des Hostnamens' })).toBeVisible()
})

test('library item: type picker, form, review, versions and rollback', async ({ page }) => {
  const name = `agent-${stamp}`
  await page.goto('/app/config?tab=library')
  await page.getByRole('button', { name: 'Neues Element' }).click()
  await page.getByRole('dialog').getByPlaceholder('Typ suchen').fill('Agent')
  await page.getByRole('dialog').getByRole('button', { name: /Agent/ }).first().click()
  await page.getByRole('textbox', { name: 'Name (Pflichtfeld)' }).fill(name)
  await page.getByLabel('Check in Intervall').fill('10')
  await expect(page.getByText('Mindestens 30')).toBeVisible()
  await page.getByLabel('Check in Intervall').fill('600')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText(`Gespeichert: ${name}`)).toBeVisible()
  await expect(page).toHaveURL(/\/config\/library\/\d+$/)

  // a change: the review shows the diff, then save it
  await page.getByLabel('Check in Intervall').fill('900')
  await page.getByRole('tab', { name: 'Änderungen' }).click()
  await expect(page.getByRole('figure').getByText('"checkin_seconds": 900')).toBeVisible()
  await shoot(page, 'library-item')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText(`Gespeichert: ${name}`).first()).toBeVisible()

  // JSON expert mode holds the same state
  await page.getByRole('radio', { name: 'JSON' }).click()
  await expect(page.getByLabel('Einstellungen als JSON')).toHaveValue(/"checkin_seconds": 900/)
  await page.getByRole('radio', { name: 'Formular' }).click()

  await page.getByRole('tab', { name: 'Versionen' }).click()
  const hist = page.getByRole('table', { name: 'Versionen' })
  await expect(hist.getByRole('row', { name: /^2 / })).toBeVisible()
  await hist.getByRole('row', { name: /^1 / }).getByRole('button', { name: 'Zurückrollen' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Zurückrollen' }).click()
  await expect(page.getByText('Version gespeichert')).toBeVisible()
  await expect(hist.getByRole('row', { name: /^3 / })).toBeVisible()

  await page.goto('/app/config?tab=library&q=' + name)
  await expect(page.getByRole('link', { name: new RegExp(name) })).toBeVisible()
  await shoot(page, 'library')
})

test('blueprint: tree with a condition, review and save', async ({ page }) => {
  const name = `bp-${stamp}`
  await page.goto('/app/config/blueprints/new')
  await page.getByRole('textbox', { name: 'Name (Pflichtfeld)' }).fill(name)
  await page.getByRole('button', { name: 'Elemente', exact: true }).click()
  await page.getByRole('combobox', { name: 'Element hinzufügen' }).first().selectOption({ label: `agent-${stamp}` })
  await page.getByRole('button', { name: 'Bedingung', exact: true }).last().click()
  await page.getByRole('combobox', { name: 'Merkmal der Regel 1' }).selectOption('tag')
  await page.getByRole('textbox', { name: 'Wert der Regel 1' }).fill('prod')
  await expect(page.getByText('Neue Elemente:')).toBeVisible()
  await shoot(page, 'blueprint-editor')
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText(`Gespeichert: ${name}`)).toBeVisible()
  await page.goto('/app/config')
  await expect(page.getByRole('heading', { name })).toBeVisible()
  await expect(page.getByText('jedes Gerät ohne andere Zuordnung')).toBeVisible()
  await shoot(page, 'blueprints')
})

test('software: store settings, a remote and a package upload', async ({ page }) => {
  await page.goto('/app/config?tab=software&sub=settings')
  const sw = page.getByRole('switch', { name: 'Stores nur lesend' })
  const before = await sw.getAttribute('aria-checked')
  await sw.click()
  await expect(page.getByText('Einstellungen gespeichert und aktiv')).toBeVisible()
  await expect(sw).not.toHaveAttribute('aria-checked', before ?? '')
  await sw.click()

  await page.goto('/app/config?tab=software&sub=remotes')
  await page.getByRole('button', { name: 'Remote hinzufügen' }).click()
  const dlg = page.getByRole('dialog')
  await dlg.getByRole('textbox', { name: /^Name/ }).fill(`corp${stamp}`)
  await dlg.getByLabel('URL').fill('https://repo.example.com/corp.flatpakrepo')
  await dlg.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText(`Remote corp${stamp} gespeichert`)).toBeVisible()
  await page.goto('/app/config?tab=software')
  await shoot(page, 'software')

  await page.goto('/app/config?tab=packages')
  await page.locator('input[type=file]').setInputFiles({ name: `hello-${stamp}.sh`, mimeType: 'text/x-shellscript', buffer: Buffer.from(`#!/bin/sh\necho ${stamp}\n`) })
  await expect(page.getByLabel('Art', { exact: true })).toHaveValue('script')
  await page.getByRole('button', { name: 'Hochladen', exact: true }).click()
  await expect(page.getByText(/Hochgeladen/).first()).toBeVisible()
  await expect(page.getByRole('cell', { name: new RegExp(`hello-${stamp}`) }).first()).toBeVisible()
  await shoot(page, 'packages')

  // an item that installs the upload, prefilled from the package list
  await page.getByRole('row', { name: new RegExp(`hello-${stamp}`) }).getByRole('link', { name: 'Element anlegen' }).click()
  await expect(page.getByRole('textbox', { name: 'Name (Pflichtfeld)' })).toHaveValue(`hello-${stamp}`)
  await page.getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText(`Gespeichert: hello-${stamp}`)).toBeVisible()
  await page.goto('/app/config?tab=packages')
  await expect(page.getByRole('button', { name: `hello-${stamp} löschen` })).toBeDisabled()
})

test('software: approve and install a user request', async ({ page }) => {
  const repo = join(import.meta.dirname, '..', '..')
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'requests.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
  await page.goto('/app/config?tab=software&sub=requests')
  const row = page.getByRole('listitem').filter({ hasText: 'E2E Notes' }).filter({ hasText: 'e2e-req1' })
  await expect(row.getByText('ausstehend')).toBeVisible()
  await expect(row.getByRole('button', { name: 'Freigeben', exact: true })).toBeVisible()
  await row.getByRole('button', { name: 'Freigeben und installieren' }).click()
  await expect(page.getByText('Freigegeben, wird installiert')).toBeVisible()
  await expect(row.getByText('wird installiert')).toBeVisible()
  await expect(row.getByRole('button', { name: 'Freigeben und installieren' })).toHaveCount(0)
  const audit = await page.evaluate(async () => (await (await fetch('/api/v1/audit?limit=20')).json()) as { items: { action: string; target: string }[] })
  expect(audit.items.some((a) => a.action === 'catalog.request.approve+install' && a.target === 'e2e-req1')).toBe(true)
})

test('files item: template preview for one device', async ({ page }) => {
  const repo = join(import.meta.dirname, '..', '..')
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'devices.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
  await page.goto('/app/config/library/new?type=com.limdm.files')
  await page.getByRole('radio', { name: 'JSON' }).click()
  await page.getByLabel('Einstellungen als JSON').fill(JSON.stringify({ files: [{ path: '/etc/motd', content: 'host {{.Hostname}} {{default "-" (index .Attributes "site")}}', mode: '0644', template: true }] }))
  await page.getByRole('radio', { name: 'Formular' }).click()
  const preview = page.getByRole('region', { name: 'Vorschau der Vorlage' })
  await preview.getByLabel('Gerät (Hostname oder ID)').fill('e2e-ws1')
  await preview.getByRole('button', { name: 'Erzeugen' }).click()
  await expect(preview.getByText('host e2e-ws1 -')).toBeVisible()
  await shoot(page, 'template-preview')
  // a missing attribute is an error, and the device keeps what it has
  await page.getByRole('radio', { name: 'JSON' }).click()
  await page.getByLabel('Einstellungen als JSON').fill(JSON.stringify({ files: [{ path: '/etc/motd', content: '{{.Attributes.site}}', mode: '0644', template: true }] }))
  await preview.getByRole('button', { name: 'Erzeugen' }).click()
  await expect(preview.getByRole('alert')).toContainText('Nicht erzeugt')
})

test('dark theme of the main screen', async ({ page }) => {
  test.skip(!shots, 'screenshots only')
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.goto('/app/config')
  await expect(page.getByRole('heading', { name: `bp-${stamp}` })).toBeVisible()
  await shoot(page, 'blueprints-dark')
  await page.goto('/app/config?tab=library')
  await shoot(page, 'library-dark')
})
