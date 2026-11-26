import { readFileSync } from 'node:fs'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// The policy the Go server sends for every console response; the dev server
// and the preview send it too, so a violation shows up before the build.
export const CSP = [
  "default-src 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'none'",
].join('; ')

// Dev server against a local LiMDM server (docs/development.md): the server's
// LIMDM_PUBLIC_URL must be this dev server's https origin, so the Origin
// check of the session API passes.
const backend = process.env.LIMDM_DEV_BACKEND ?? 'https://localhost:8080'
const cert = process.env.LIMDM_DEV_CERT
const key = process.env.LIMDM_DEV_KEY
const proxy = Object.fromEntries(
  ['/api', '/login', '/logout', '/auth', '/static', '/lang', '/tenants/switch', '/branding'].map((p) => [p, { target: backend, secure: false }]),
)

export default defineConfig({
  base: '/app/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: '../internal/server/webapp/dist',
    emptyOutDir: true,
    target: 'es2022',
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0, // no data: URIs
    sourcemap: false,
  },
  server: {
    headers: { 'Content-Security-Policy': CSP },
    https: cert && key ? { cert: readFileSync(cert), key: readFileSync(key) } : undefined,
    proxy,
  },
  preview: { headers: { 'Content-Security-Policy': CSP } },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['src/test/setup.ts'],
  },
})
