// Main flows of the vulnerabilities page against the real server: cards,
// filters, the detail sheet with CVSS and KEV, accepting a risk and
// reopening it, remediated findings.
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath, locale: 'de-DE' })

test.beforeAll(() => {
  const repo = join(import.meta.dirname, '..', '..')
  execFileSync('go', ['run', './scripts/e2eseed', join(import.meta.dirname, 'vulnerabilities.seed.sql')], { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } })
})

const isoIn = (days: number) => {
  const d = new Date(Date.now() + days * 86_400_000)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

test('cards, filters and the detail sheet', async ({ page }) => {
  await page.goto('/app/vulnerabilities')
  await expect(page.getByRole('heading', { name: 'Schwachstellen', level: 1 })).toBeVisible()
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Schwachstellen' })).toBeVisible()
  await expect(page.getByText('Schwachstellen nach Schweregrad')).toBeVisible()
  await expect(page.getByText('Stand der Behebung')).toBeVisible()
  const grid = page.getByRole('table', { name: 'Schwachstellen' })
  await expect(grid.getByRole('button', { name: 'CVE-2099-0002', exact: true })).toBeVisible()
  // remediated findings are not in the default (active) view
  await expect(grid.getByRole('button', { name: 'CVE-2099-0004', exact: true })).toHaveCount(0)

  // the top software bars filter the table
  await page.getByRole('button', { name: /^libxml2: 1 CVEs/ }).click()
  await expect(page).toHaveURL(/pkg=libxml2/)
  await expect(grid.getByRole('button', { name: 'CVE-2099-0001', exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Filter zurücksetzen' }).click()
  await expect(grid.getByRole('button', { name: 'CVE-2099-0001', exact: true })).toBeVisible()

  // known exploited only, then search
  await page.getByLabel('Nur bekannt ausgenutzte').check()
  await expect(page).toHaveURL(/kev=on/)
  await expect(grid.getByRole('button', { name: 'CVE-2099-0003', exact: true })).toHaveCount(0)
  await page.getByLabel('Nur bekannt ausgenutzte').uncheck()
  await page.getByLabel('CVE oder Software suchen').fill('curl')
  await expect(page).toHaveURL(/q=curl/)
  await expect(grid.getByRole('button', { name: 'CVE-2099-0003', exact: true })).toBeVisible()
  await expect(grid.getByRole('button', { name: 'CVE-2099-0002', exact: true })).toHaveCount(0)
  await page.getByLabel('CVE oder Software suchen').fill('')

  // severity from the CVSS score where no source states one; KEV in the sheet
  await grid.getByRole('button', { name: 'CVE-2099-0002', exact: true }).click()
  await expect(page).toHaveURL(/sel=CVE-2099-0002/)
  const sheet = page.getByRole('complementary')
  await expect(sheet.getByText('9,8')).toBeVisible()
  await expect(sheet.getByText('Kritisch')).toBeVisible()
  await expect(sheet.getByText('libxml2 test entry')).toBeVisible()
  await expect(sheet.getByText('Von Ransomware genutzt')).toBeVisible()
  await expect(sheet.getByRole('link', { name: 'e2e-vu1' })).toBeVisible()
  await expect(sheet.getByRole('link', { name: /NVD/ })).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2099-0002')
})

test('accept a risk, see it accepted, reopen it', async ({ page }) => {
  await page.goto('/app/vulnerabilities')
  const grid = page.getByRole('table', { name: 'Schwachstellen' })
  await grid.getByRole('button', { name: 'Aktionen für CVE-2099-0003' }).click()
  await page.getByRole('menuitem', { name: 'Risiko akzeptieren' }).click()
  const dialog = page.getByRole('dialog', { name: 'Risiko für CVE-2099-0003 akzeptieren' })
  await dialog.getByRole('button', { name: 'Risiko akzeptieren' }).click()
  await expect(dialog.getByText('Eine Begründung angeben (bis 1000 Zeichen).')).toBeVisible()
  await dialog.getByLabel('Begründung').fill('curl only used offline in the lab')
  await dialog.getByLabel('Gültig bis').fill(isoIn(30))
  await dialog.getByRole('button', { name: 'Risiko akzeptieren' }).click()
  await expect(page.getByText('Risiko für CVE-2099-0003 akzeptiert')).toBeVisible()
  await expect(grid.getByRole('button', { name: 'CVE-2099-0003', exact: true })).toHaveCount(0)

  await page.getByLabel('Status', { exact: true }).selectOption('accepted')
  await expect(page).toHaveURL(/status=accepted/)
  await grid.getByRole('button', { name: 'CVE-2099-0003', exact: true }).click()
  const sheet = page.getByRole('complementary')
  await expect(sheet.getByText('curl only used offline in the lab')).toBeVisible()
  await sheet.getByRole('button', { name: 'Wieder öffnen' }).click()
  await page.getByRole('dialog', { name: 'CVE-2099-0003 wieder öffnen?' }).getByRole('button', { name: 'Wieder öffnen' }).click()
  await expect(page.getByText('CVE-2099-0003 wieder geöffnet')).toBeVisible()
  await expect(grid.getByRole('button', { name: 'CVE-2099-0003', exact: true })).toHaveCount(0)
})

test('remediated findings with the date', async ({ page }) => {
  await page.goto('/app/vulnerabilities?status=remediated')
  const grid = page.getByRole('table', { name: 'Schwachstellen' })
  await grid.getByRole('button', { name: 'CVE-2099-0004', exact: true }).click()
  await expect(page.getByRole('complementary').getByText(/Behoben am/)).toBeVisible()
})
