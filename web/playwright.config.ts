import { defineConfig, devices } from '@playwright/test'

// End to end tests against a real LiMDM server on its own database
// (LIMDM_E2E_DATABASE_URL, never a production one). e2e/global-setup.ts
// builds the server, starts it with TLS on localhost and signs in.
export const port = Number(process.env.LIMDM_E2E_PORT ?? 18480)
export const baseURL = `https://localhost:${port}`

export default defineConfig({
  testDir: 'e2e',
  outputDir: 'test-results/output',
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]] : 'list',
  use: {
    baseURL,
    ignoreHTTPSErrors: true, // self signed certificate of the test server
    trace: 'retain-on-failure',
    locale: 'de-DE',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
