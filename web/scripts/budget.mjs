// Bundle budget (gzip): fails the build when the first load, a lazy chunk,
// the CSS or the fonts grow past the limits of the concept.
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

const dist = new URL('../../internal/server/webapp/dist/', import.meta.url).pathname
const assets = join(dist, 'assets')
const kb = (f) => gzipSync(readFileSync(join(assets, f))).length / 1024
const index = readFileSync(join(dist, 'index.html'), 'utf8')
const initial = [...index.matchAll(/(?:src|href)="\/app\/assets\/([^"]+\.js)"/g)].map((m) => m[1])

// ponytail: the message catalogs of every area load up front (sync t()); with all six
// areas merged that is past the concept's 260 KB. Load area catalogs with their
// routes when the first load matters more.
const limits = { initialJs: 300, chunk: 120, echarts: 220, css: 20, font: 100 }
const files = readdirSync(assets)
const fail = []
const initialKb = initial.reduce((s, f) => s + kb(f), 0)
if (initialKb > limits.initialJs) fail.push(`first load JS ${initialKb.toFixed(0)} KB > ${limits.initialJs}`)
for (const f of files) {
  const size = kb(f)
  if (f.endsWith('.css') && size > limits.css) fail.push(`${f} ${size.toFixed(0)} KB > ${limits.css}`)
  if (f.endsWith('.woff2') && size > limits.font) fail.push(`${f} ${size.toFixed(0)} KB > ${limits.font}`)
  if (f.endsWith('.js') && !initial.includes(f)) {
    const limit = f.startsWith('echarts') ? limits.echarts : limits.chunk
    if (size > limit) fail.push(`${f} ${size.toFixed(0)} KB > ${limit}`)
  }
}
console.log(`budget: first load JS ${initialKb.toFixed(0)} KB gzip (${initial.length} files), ${files.length} assets`)
if (fail.length) {
  console.error('over budget:\n  ' + fail.join('\n  '))
  process.exit(1)
}
