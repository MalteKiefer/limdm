// The API reference at /api/v1/docs: Swagger UI from the server's own
// static files under the strict CSP. Authorize with a token created here and
// run "Try it out" on GET /api/v1/devices; opened signed in, calls without a
// token use the console session.
import { expect, test, type Page } from '@playwright/test'
import { baseURL } from '../playwright.config'
import { statePath } from './global-setup'
import { signIn } from './signin'

async function watch(page: Page) {
  const violations: string[] = []
  page.on('console', (m) => {
    if (/Content Security Policy|Content-Security-Policy/i.test(m.text())) violations.push(m.text())
  })
  page.on('pageerror', (e) => violations.push(`page error: ${e.message}`))
  page.on('request', (r) => {
    if (!r.url().startsWith(baseURL) && !r.url().startsWith('data:') && !r.url().startsWith('blob:')) violations.push(`third party request: ${r.url()}`)
  })
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      ;(window as unknown as { __csp: string[] }).__csp ??= []
      ;(window as unknown as { __csp: string[] }).__csp.push(`${e.violatedDirective} ${e.blockedURI}`)
    })
  })
  return async () => [...violations, ...((await page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp)) ?? [])]
}

async function tryIt(page: Page, id: string) {
  const op = page.locator(`.opblock[id$="-${id}"]`)
  await expect(op).toBeVisible()
  if (!(await op.getAttribute('class'))?.includes('is-open')) await op.locator('.opblock-summary').first().click()
  await op.getByRole('button', { name: 'Try it out' }).click()
  await op.getByRole('button', { name: 'Execute' }).click()
  return op.locator('.live-responses-table tbody .response-col_status').first()
}

test('authorize with a token and try GET /api/v1/devices within the CSP', async ({ browser }) => {
  const admin = await signIn('e2eapidocs')
  const csrf = ((await (await admin.get('/api/v1/me')).json()) as { csrf_token: string }).csrf_token
  const res = await admin.post('/api/v1/tokens', { data: { name: 'e2e-apidocs', role: 'auditor', days: 1 }, headers: { 'X-CSRF-Token': csrf, Origin: baseURL } })
  expect(res.status(), await res.text()).toBe(201)
  const { token } = (await res.json()) as { token: string }

  // no session: only the token authorizes
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
  const page = await ctx.newPage()
  const collect = await watch(page)
  const doc = await page.goto('/api/v1/docs')
  expect(doc?.headers()['content-security-policy']).toBe("default-src 'self'; img-src 'self' data: blob:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
  await expect(page).toHaveTitle('LiMDM Admin API')
  await expect(page.getByRole('link', { name: 'Back to the console' })).toHaveAttribute('href', '/app/')
  await expect(page.locator('.swagger-ui .info .title')).toContainText('LiMDM Admin API')
  await expect(page.locator('.swagger-ui .topbar')).toHaveCount(0)

  await page.locator('.swagger-ui .scheme-container button.authorize').click()
  const bearer = page.locator('.modal-ux .auth-container').filter({ hasText: 'bearer' })
  await bearer.locator('input').fill(token)
  await bearer.getByRole('button', { name: 'Apply credentials' }).click()
  await bearer.getByRole('button', { name: 'Close' }).click()

  await expect(await tryIt(page, 'listDevices')).toHaveText('200')
  // the token is not persisted
  expect(await page.evaluate(() => localStorage.getItem('authorized'))).toBeNull()
  expect(await collect()).toEqual([])
  await ctx.close()
  await admin.dispose()
})

test('signed in, calls without a token use the console session', async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, storageState: statePath })
  const page = await ctx.newPage()
  const collect = await watch(page)
  await page.goto('/api/v1/docs')
  await expect(page.locator('#apidocs-session')).toContainText('Signed in as')
  await expect(await tryIt(page, 'listDevices')).toHaveText('200')
  // a state change carries the session's CSRF token (requestInterceptor);
  // Swagger UI renders only the tags in view, a deep link opens the operation
  await page.goto('about:blank')
  await page.goto('/api/v1/docs#/Audit%20and%20activity/auditVerify')
  await expect(page.locator('#apidocs-session')).toContainText('Signed in as')
  await expect(await tryIt(page, 'auditVerify')).toHaveText('200')
  expect(await collect()).toEqual([])
  await ctx.close()
})

test('the user menu links to the API reference', async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'de-DE', storageState: statePath })
  const page = await ctx.newPage()
  await page.goto('/app/')
  await page.getByRole('button', { name: /Benutzermenü|User menu/ }).first().click()
  await page.getByRole('menuitem', { name: 'API Referenz' }).click()
  await expect(page).toHaveURL(/\/api\/v1\/docs$/)
  await ctx.close()
})
