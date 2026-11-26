// Every page and the shared components run under the console's strict CSP
// (default-src 'self', no inline script or style, no eval). The test fails
// on any violation the browser reports.
import { expect, test, type Page } from '@playwright/test'
import { statePath } from './global-setup'

test.use({ storageState: statePath })

const pages = ['/app/', '/app/inbox', '/app/devices', '/app/devices/x1', '/app/compliance', '/app/config', '/app/config?tab=library', '/app/config?tab=software', '/app/config?tab=packages', '/app/config/blueprints/new', '/app/config/library/new?type=com.limdm.network', '/app/config/software/new', '/app/activity', '/app/reports', '/app/settings', '/app/dev/components', '/app/no-such-page']

async function watch(page: Page) {
  const violations: string[] = []
  page.on('console', (m) => {
    if (/Content Security Policy|Content-Security-Policy/i.test(m.text())) violations.push(m.text())
  })
  page.on('pageerror', (e) => violations.push(`page error: ${e.message}`))
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      ;(window as unknown as { __csp: string[] }).__csp ??= []
      ;(window as unknown as { __csp: string[] }).__csp.push(`${e.violatedDirective} ${e.blockedURI}`)
    })
  })
  return async () => [...violations, ...((await page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp)) ?? [])]
}

test('every page renders without a CSP violation', async ({ page }) => {
  const collect = await watch(page)
  for (const p of pages) {
    const res = await page.goto(p)
    expect(res?.headers()['content-security-policy']).toContain("default-src 'self'")
    await expect(page.getByRole('navigation', { name: /Hauptnavigation|Main navigation/ }).first()).toBeVisible()
    await page.waitForLoadState('networkidle')
  }
  expect(await collect()).toEqual([])
})

test('the detector sees a violation', async ({ page }) => {
  const collect = await watch(page)
  await page.goto('/app/')
  await page.evaluate(() => {
    const s = document.createElement('style')
    s.textContent = 'body { color: red }'
    document.head.append(s)
  })
  await expect.poll(async () => (await collect()).length).toBeGreaterThan(0)
})

test('palette, menus, dialogs, charts and dark theme stay within the CSP', async ({ page }) => {
  const collect = await watch(page)
  await page.goto('/app/dev/components')
  await page.keyboard.press('Control+k')
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.keyboard.type('Ger')
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: /Benutzermenü|User menu/ }).first().click()
  await page.getByRole('menuitem', { name: /Dunkles Design|Dark theme/ }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.getByRole('button', { name: 'Fertig' }).or(page.getByRole('button', { name: 'Weiter' })).first().click()
  await page.getByRole('row', { name: /host-0001/ }).click()
  await expect(page.getByRole('complementary', { name: 'host-0001' })).toBeVisible()
  await page.keyboard.press('j')
  await expect(page.getByRole('complementary', { name: 'host-0002' })).toBeVisible()
  await page.getByRole('button', { name: /Als Tabelle|As table/ }).first().click()
  await page.getByRole('button', { name: 'Toast' }).click()
  await page.waitForTimeout(500)
  expect(await collect()).toEqual([])
})
