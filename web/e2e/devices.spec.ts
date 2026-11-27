// Main flows of the devices area against the real server: the list with
// German query terms, package filter, facets and side sheet; bulk actions;
// the device page with tabs and dialogs; retire and delete; enrollment.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath, locale: 'de-DE' })

test.beforeAll(() => {
  const repo = join(import.meta.dirname, '..', '..')
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'devices.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
})

test('list: query language, package filter, facets, side sheet', async ({ page }) => {
  await page.goto('/app/devices')
  const grid = page.getByRole('table', { name: 'Geräte' })
  await expect(grid.getByRole('link', { name: 'e2e-ws1' })).toBeVisible()
  await expect(grid.getByRole('link', { name: 'e2e-srv1' })).toBeVisible()

  // German status alias, server side
  const q = page.getByRole('combobox', { name: /Abfrage|Query/ })
  await q.fill('status:nicht-konform')
  await q.press('Enter')
  await expect(page).toHaveURL(/q=status%3Anicht-konform/)
  await expect(grid.getByRole('link', { name: 'e2e-ws2' })).toBeVisible()
  await expect(grid.getByRole('link', { name: 'e2e-ws1' })).toHaveCount(0)
  await page.getByRole('button', { name: /Filter zurücksetzen|Reset filter/ }).first().click()

  // package version filter: only the device with the old openssl
  await page.getByLabel('Paketfilter').fill('openssl < 3.0.13')
  await page.getByRole('button', { name: 'Filtern' }).click()
  await expect(grid.getByRole('link', { name: 'e2e-ws1' })).toBeVisible()
  await expect(grid.getByRole('link', { name: 'e2e-ws2' })).toHaveCount(0)
  await page.goto('/app/devices')

  // a facet adds a term
  await page.getByRole('navigation', { name: /Facetten|Facets/ }).getByRole('button', { name: /berlin/ }).click()
  await expect(page).toHaveURL(/tag%3Aberlin/)
  await expect(grid.getByRole('link', { name: 'e2e-ws2' })).toHaveCount(0)

  // the side sheet opens on a row click and closes with Escape
  await grid.getByRole('row', { name: /e2e-ws1/ }).click()
  const sheet = page.getByRole('complementary', { name: 'e2e-ws1' })
  await expect(sheet).toBeVisible()
  await expect(sheet.getByText('PF12345')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(sheet).toHaveCount(0)
})

test('bulk: sync and tag the selected devices', async ({ page }) => {
  await page.goto('/app/devices?q=tag%3Aprod')
  const grid = page.getByRole('table', { name: 'Geräte' })
  await expect(grid.getByRole('link', { name: 'e2e-ws1' })).toBeVisible()
  await grid.getByRole('row', { name: /e2e-ws1/ }).getByRole('checkbox').check()
  await grid.getByRole('row', { name: /e2e-ws2/ }).getByRole('checkbox').check()
  const bar = page.getByRole('region', { name: /2 ausgewählt|2 selected/ })
  await bar.getByRole('button', { name: 'Jetzt synchronisieren' }).click()
  await expect(page.getByText('An 2 Geräte gesendet')).toBeVisible()

  await grid.getByRole('row', { name: /e2e-ws1/ }).getByRole('checkbox').check()
  await page.getByRole('region', { name: /1 ausgewählt|1 selected/ }).getByRole('button', { name: 'Mehr' }).click()
  await page.getByRole('menuitem', { name: 'Tag hinzufügen oder entfernen' }).click()
  await page.getByRole('dialog').getByLabel('Tag').fill('e2etag')
  await page.getByRole('dialog').getByRole('button', { name: 'Hinzufügen' }).click()
  await expect(page.getByText('An 1 Gerät gesendet')).toBeVisible()
  await page.goto('/app/devices?q=tag%3Ae2etag')
  await expect(grid.getByRole('link', { name: 'e2e-ws1' })).toBeVisible()
})

test('bulk bar sits at the bottom of the content column and never covers the last row', async ({ page }) => {
  for (const scheme of ['light', 'dark'] as const) {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/app/devices?q=tag%3Aprod')
    await page.getByRole('table', { name: 'Geräte' }).getByRole('row', { name: /e2e-ws1/ }).getByRole('checkbox').check()
    const bar = page.getByRole('region', { name: /1 ausgewählt/ })
    // phones show cards without checkboxes; the selection made wide stays when the window narrows
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 900 })
      await expect(bar).toBeVisible()
      // flush with the viewport bottom once the fade in settled
      await expect.poll(async () => { const r = (await bar.boundingBox())!; return Math.round(r.y + r.height) }).toBe(900)
      const b = (await bar.boundingBox())!
      if (width === 1440) expect(b.x).toBeGreaterThanOrEqual(200) // right of the sidebar
      // scrolled to the end, the last row or card stays above the bar
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight))
      const rows = width === 1440 ? page.getByRole('table', { name: 'Geräte' }).getByRole('row') : page.getByRole('list', { name: 'Geräte' }).getByRole('listitem')
      const last = (await rows.last().boundingBox())!
      expect(last.y + last.height).toBeLessThanOrEqual((await bar.boundingBox())!.y + 1)
      await page.screenshot({ path: `test-results/bulk-${width}-${scheme}.png` })
    }
    await bar.getByRole('button', { name: 'Auswahl aufheben' }).click()
    await expect(bar).toHaveCount(0)
  }
})

test('device page: tabs, message, details, activity', async ({ page }) => {
  await page.goto('/app/devices/e2e-ws1')
  await expect(page.getByRole('heading', { level: 1, name: 'e2e-ws1' })).toBeVisible()
  for (const tab of ['Compliance', 'Konfiguration', 'Software', 'Inventar', 'Aktivität', 'Übersicht']) {
    await page.getByRole('tab', { name: new RegExp(`^${tab}`) }).click()
    await expect(page).toHaveURL(tab === 'Übersicht' ? /\/devices\/e2e-ws1$/ : /tab=/)
  }
  // health cards of the overview: words, not only colours
  await expect(page.getByText('Firewall', { exact: true })).toBeVisible()
  await expect(page.getByText('Aktiv', { exact: true })).toBeVisible()
  await expect(page.getByText('Verbunden', { exact: true })).toBeVisible()

  await page.getByRole('tab', { name: 'Software' }).click()
  await expect(page.getByText('openssl')).toBeVisible()
  // removing asks in the console's dialog, not the browser's confirm()
  await page.getByRole('row', { name: /openssl/ }).getByRole('button', { name: 'Entfernen' }).click()
  await expect(page.getByRole('dialog', { name: 'openssl von diesem Gerät entfernen?' })).toBeVisible()
  await page.getByRole('dialog').getByRole('button', { name: 'Abbrechen' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)

  // send a message through the action menu
  await page.getByRole('button', { name: 'Aktionen für e2e-ws1' }).click()
  await page.getByRole('menuitem', { name: 'Nachricht senden' }).click()
  await page.getByRole('dialog').getByLabel('Nachricht', { exact: false }).last().fill('Bitte neu starten')
  await page.getByRole('dialog').getByRole('button', { name: 'Senden' }).click()
  await expect(page.getByText('An e2e-ws1 gesendet', { exact: false })).toBeVisible()

  // edit details: tags
  await page.getByRole('button', { name: 'Aktionen für e2e-ws1' }).click()
  await page.getByRole('menuitem', { name: 'Gerätedetails bearbeiten' }).click()
  await page.getByRole('dialog').getByLabel('Tags').fill('prod, berlin, edited')
  // a desktop user: the person, then the proposed user name
  await page.getByRole('dialog').getByRole('button', { name: 'Desktop Benutzer hinzufügen' }).click()
  await page.getByRole('dialog').getByLabel('Person 1 (E Mail Adresse)').fill('jane.doe@example.com')
  await page.getByRole('dialog').getByLabel('Benutzername 1').focus()
  await expect(page.getByRole('dialog').getByLabel('Benutzername 1')).toHaveValue('janedoe')
  await page.getByRole('dialog').getByRole('button', { name: 'Speichern' }).click()
  await expect(page.getByText('Gerätedetails gespeichert')).toBeVisible()
  await expect(page.getByRole('link', { name: '#edited' })).toBeVisible()

  // the activity shows the message command
  await page.getByRole('tab', { name: 'Aktivität' }).click()
  await expect(page.getByText('Nachricht', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('checked in from the e2e seed')).toBeVisible()
  // compliance changes and audit entries of the device
  await page.getByRole('radio', { name: 'Compliance' }).click()
  await expect(page.getByText('Prüfung SSH root login disabled')).toBeVisible()
  await page.getByRole('radio', { name: 'Audit' }).click()
  await expect(page.getByRole('feed').getByRole('listitem').first()).toBeVisible()
  await page.getByRole('radio', { name: 'Alle' }).click()

  // reboot later validates its delay
  await page.getByRole('button', { name: 'Aktionen für e2e-ws1' }).click()
  await page.getByRole('menuitem', { name: 'Später neu starten' }).click()
  await page.getByRole('dialog').getByLabel('Verzögerung in Minuten').fill('0')
  await expect(page.getByRole('dialog').getByRole('button', { name: 'Planen' })).toBeDisabled()
  await page.keyboard.press('Escape')
})

test('phone width: cut off tabs show a hint that scrolls them', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 })
  await page.goto('/app/devices/e2e-ws1')
  const more = page.getByRole('button', { name: 'Weitere Einträge rechts' }).first()
  await expect(more).toBeVisible()
  await more.click()
  await expect(page.getByRole('button', { name: 'Weitere Einträge links' }).first()).toBeVisible()
})

test('shell transcript: replay in a read only terminal, plain text, downloads', async ({ page }) => {
  await page.goto('/app/devices/e2e-ws1/shell/e2e-sh1')
  await expect(page.getByRole('heading', { name: 'Mitschnitt' })).toBeVisible()
  // the replay is an xterm with the canvas renderer
  await expect(page.locator('.xterm canvas').first()).toBeVisible()
  await expect.poll(async () => (await page.locator('.xterm').boundingBox())!.height).toBeLessThan(200) // sized to the content
  await page.getByRole('radio', { name: 'Nur Text' }).click()
  const text = page.locator('pre')
  await expect(text).toContainText('malte@pc ~> ls\nDocuments  a.txt  b.txt\nmalte@pc ~> exit')
  await expect(text).not.toContainText('(B')
  await expect(text).not.toContainText('⏎')
  const dl = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Rohdaten (.log)' }).click()
  expect((await dl).suggestedFilename()).toBe('shell-e2e-sh1.log')
  const dl2 = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Text (.txt)' }).click()
  expect((await dl2).suggestedFilename()).toBe('shell-e2e-sh1.txt')
})

test('retire and delete a device', async ({ page }) => {
  await page.goto('/app/devices/e2e-srv1')
  await page.getByRole('button', { name: 'Aktionen für e2e-srv1' }).click()
  await page.getByRole('menuitem', { name: 'Gerät ausmustern' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Ausmustern und Zertifikat widerrufen' }).click()
  await expect(page.getByText('Gerät ausgemustert')).toBeVisible()
  await page.getByRole('button', { name: 'Gerät löschen' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByRole('button', { name: 'Gerät löschen' })).toBeDisabled()
  await dlg.getByLabel(/Hostnamen/).fill('e2e-srv1')
  await dlg.getByRole('button', { name: 'Gerät löschen' }).click()
  await expect(page).toHaveURL(/\/app\/devices$/)
  await expect(page.getByRole('table', { name: 'Geräte' }).getByRole('link', { name: 'e2e-srv1' })).toHaveCount(0)
})

test('add device: token, install command, revoke', async ({ page }) => {
  await page.goto('/app/devices')
  await page.getByRole('link', { name: 'Gerät hinzufügen' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Gerät hinzufügen' })).toBeVisible()
  const note = `e2e batch ${Date.now()}`
  await page.getByLabel('Notiz').fill(note)
  await page.getByRole('button', { name: 'Token erstellen' }).click()
  const token = page.getByLabel('Registrierungstoken', { exact: true })
  await expect(token).toContainText('lmt_')
  const value = (await token.textContent())?.trim() ?? ''
  await expect(page.locator('#tok-install')).toContainText(`LIMDM_TOKEN=${value}`)
  await expect(page.locator('#tok-conf')).toContainText(`token = "${value}"`)
  const row = page.getByRole('row', { name: new RegExp(note) })
  await row.getByRole('button', { name: 'Token widerrufen' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Token widerrufen' }).click()
  await expect(page.getByText('Token widerrufen', { exact: true }).first()).toBeVisible()
  await expect(page.getByRole('row', { name: new RegExp(note) })).toHaveCount(0)
})
