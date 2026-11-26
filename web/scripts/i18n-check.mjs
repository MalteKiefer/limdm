// Translation extraction check. Collects every message key the code uses
// (t('key'), labels: 'key' in nav entries, `area.key` template prefixes) and
// compares with the catalogs: a used key missing in the German catalog fails
// (tsc also catches it), unused catalog keys fail too, so catalogs do not
// rot. --report prints the counts per area.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const root = new URL('../src/', import.meta.url).pathname
const files = []
const walk = (d) => {
  for (const f of readdirSync(d)) {
    const p = join(d, f)
    if (statSync(p).isDirectory()) walk(p)
    else if (/\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f) && !f.endsWith('.d.ts')) files.push(p)
  }
}
walk(root)

const catalogFiles = files.filter((f) => f.endsWith('/messages.ts') || f.endsWith('/i18n/core.ts'))
const keyRe = /^\s*'([a-z][\w.-]*(?: [\w-]+)?)':/gm
const catalog = new Map() // key -> file
for (const f of catalogFiles) {
  const src = readFileSync(f, 'utf8')
  const de = src.slice(0, src.indexOf('export const en'))
  for (const m of de.matchAll(keyRe)) catalog.set(m[1], f.replace(root, ''))
}

const used = new Set() // keys passed to t() directly: must exist
const mentioned = new Set() // any string literal that is a key (labels, ternaries in t())
const prefixes = new Set()
for (const f of files.filter((x) => !catalogFiles.includes(x))) {
  const src = readFileSync(f, 'utf8')
  for (const m of src.matchAll(/\bt[r]?\(\s*'([a-z][\w.-]*(?: [\w-]+)?)'/g)) used.add(m[1])
  for (const m of src.matchAll(/'([a-z][\w-]*\.[\w.-]+)'/g)) mentioned.add(m[1])
  // dynamic keys: t(`status.${x}`) marks the whole prefix as used
  for (const m of src.matchAll(/`([a-z][\w.]*\.)\$\{/g)) prefixes.add(m[1])
}
for (const k of mentioned) if (catalog.has(k)) used.add(k)

const missing = [...used].filter((k) => !catalog.has(k))
const unused = [...catalog.keys()].filter((k) => !used.has(k) && ![...prefixes].some((p) => k.startsWith(p)))

if (process.argv.includes('--report')) {
  const per = {}
  for (const [, f] of catalog) per[f] = (per[f] ?? 0) + 1
  console.log('keys per catalog:', per)
  console.log(`used ${used.size}, catalog ${catalog.size}`)
}
if (missing.length) console.error('used but not in a catalog:\n  ' + missing.join('\n  '))
if (unused.length) console.error('in a catalog but unused:\n  ' + unused.join('\n  '))
if (missing.length || unused.length) process.exit(1)
