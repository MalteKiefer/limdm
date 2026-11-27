// Translation extraction check. Collects every message key the code uses
// (t('key'), labels: 'key' in nav entries, `area.key` template prefixes) and
// compares with the catalogs: a used key missing in the German catalog fails
// (tsc also catches it), unused catalog keys fail too, so catalogs do not
// rot. --report prints the counts per area.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'

const root = new URL('../src/', import.meta.url).pathname
const files = []
const walk = (d) => {
  for (const f of readdirSync(d)) {
    const p = join(d, f)
    if (statSync(p).isDirectory()) walk(p)
    // translations (messages.fr.ts, core.ru.ts ...) mirror the German keys: tsc and the vitest check them
    else if (/\.(ts|tsx)$/.test(f) && !/\.test\.tsx?$/.test(f) && !f.endsWith('.d.ts') && !/\.[a-z]{2}\.ts$/.test(f)) files.push(p)
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

// Hardcoded texts: JSX text and the visible attributes (aria-label, title,
// placeholder, alt, label props) must come from t(). Product names, units
// and symbols pass; a line ending in `// i18n-ok` is a deliberate exception.
const visibleAttrs = new Set(['aria-label', 'title', 'placeholder', 'alt', 'label', 'hint', 'description', 'emptyText'])
const allowed = /^(LiMDM|SHA-256|JSON|YAML|CSV|PDF|SSH|TOTP|OIDC|SCIM|TPM|URL|ID|API|CVE|LUKS|Ed25519|PEM|Google Workspace|Object Lock|Cron|ISO 27001|Esc|Snap|&nbsp;|[A-Z]+|·|…|—|→|←|×|\+|-|%|\/|:|#|[a-z][\w.-]*|[\d\s.,:/%+×-]+)$/
// placeholders that show an example value (host, address, path, key) are data
const example = /[@/:{}=<>;\n]|…|^\S+\.\S+$|\d|^-----|^[A-Z]+$/
const hardcoded = []
for (const f of files.filter((x) => !catalogFiles.includes(x) && !x.endsWith('/gallery.tsx'))) {
  const src = readFileSync(f, 'utf8')
  const sf = ts.createSourceFile(f, src, ts.ScriptTarget.Latest, true, f.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
  const report = (node, text) => {
    const s = text.replace(/\s+/g, ' ').trim()
    if (!/\p{L}{2,}/u.test(s) || allowed.test(s) || /^(https?:\/\/|\/)\S*$/.test(s)) return
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart())
    if (src.split('\n')[line].includes('i18n-ok')) return
    hardcoded.push(`${f.replace(root, '')}:${line + 1}: ${s.slice(0, 80)}`)
  }
  const visit = (node) => {
    if (ts.isJsxElement(node) && /^(code|pre|kbd|samp)$/.test(node.openingElement.tagName.getText())) return // literal code
    if (ts.isJsxText(node)) report(node, node.text)
    else if (ts.isJsxExpression(node) && node.expression && !ts.isJsxAttribute(node.parent)) {
      // {'text'}, {a ? 'yes' : 'no'}, {a && 'text'}, {a ?? 'text'} as element children
      const leaves = (e) => (ts.isParenthesizedExpression(e) ? leaves(e.expression) : ts.isConditionalExpression(e) ? [...leaves(e.whenTrue), ...leaves(e.whenFalse)] : ts.isBinaryExpression(e) ? leaves(e.right) : [e])
      for (const e of leaves(node.expression)) if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) report(e, e.text)
    }
    else if (ts.isJsxAttribute(node) && visibleAttrs.has(node.name.getText()) && node.initializer) {
      const init = node.initializer
      const attr = node.name.getText()
      const check = (n, text) => (attr === 'placeholder' && example.test(text) ? undefined : report(n, text))
      if (ts.isStringLiteral(init)) check(init, init.text)
      else if (ts.isJsxExpression(init) && init.expression && (ts.isStringLiteral(init.expression) || ts.isNoSubstitutionTemplateLiteral(init.expression))) check(init, init.expression.text)
    } else if (ts.isPropertyAssignment(node) && visibleAttrs.has(node.name.getText()) && ts.isStringLiteral(node.initializer)) report(node.initializer, node.initializer.text)
    else if (ts.isCallExpression(node) && /^(toast|confirm|alert)$/.test(node.expression.getText()) && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) report(node.arguments[0], node.arguments[0].text)
    ts.forEachChild(node, visit)
  }
  visit(sf)
}

if (process.argv.includes('--report')) {
  const per = {}
  for (const [, f] of catalog) per[f] = (per[f] ?? 0) + 1
  console.log('keys per catalog:', per)
  console.log(`used ${used.size}, catalog ${catalog.size}`)
}
if (missing.length) console.error('used but not in a catalog:\n  ' + missing.join('\n  '))
if (unused.length) console.error('in a catalog but unused:\n  ' + unused.join('\n  '))
if (hardcoded.length) console.error('hardcoded texts (use t() or mark // i18n-ok):\n  ' + hardcoded.join('\n  '))
if (missing.length || unused.length || hardcoded.length) process.exit(1)
